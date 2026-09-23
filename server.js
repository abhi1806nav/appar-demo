const express = require("express");
const axios = require("axios");
const FormData = require("form-data");
const crypto = require("crypto");

const app = express();

app.use(express.json());

const GOOGLE_SHEET_URL =
  "https://script.google.com/macros/s/AKfycbzee7qiMQT2CcBXixoDhNLg6uEmnVz1acOCroBc70QQAJnuia5Eo3HvcK23Mio98jwK/exec";

const OAUTH_URL = "https://nadapi.digilocker.gov.in/v1/oauth";

// If an API URL ever changes, set it in Render environment variables
const VERIFY_URL =
  process.env.VERIFY_URL ||
  "https://nadapi.digilocker.gov.in/v1/VerifyApaar";

const CREATE_URL =
  process.env.CREATE_URL ||
  "https://nadapi.digilocker.gov.in/v1/createABCIDByAadhaar";

app.get("/", (req, res) => {
  res.sendFile(__dirname + "/index.html");
});

// =====================================================
// ENCRYPTION (AES-256-GCM) - same as the PHP reference
// =====================================================

// Make the key exactly 32 bytes, like PHP does
// (short key -> padded with null bytes, long key -> cut to 32)
function getKeyBuffer(key) {
  const keyBuf = Buffer.alloc(32);
  Buffer.from(String(key), "utf8").copy(keyBuf, 0, 0, 32);
  return keyBuf;
}

function encrypt(data, key) {
  const iv = crypto.randomBytes(12); // 12-byte IV

  const cipher = crypto.createCipheriv(
    "aes-256-gcm",
    getKeyBuffer(key),
    iv,
    { authTagLength: 16 }
  );

  const cipherText = Buffer.concat([
    cipher.update(data, "utf8"),
    cipher.final()
  ]);

  const tag = cipher.getAuthTag(); // 16-byte tag

  // IV + CipherText + Tag -> Base64
  return Buffer.concat([iv, cipherText, tag]).toString("base64");
}

function decrypt(encryptedData, key) {
  const combined = Buffer.from(encryptedData, "base64");

  const iv = combined.subarray(0, 12);
  const tag = combined.subarray(combined.length - 16);
  const cipherText = combined.subarray(12, combined.length - 16);

  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    getKeyBuffer(key),
    iv,
    { authTagLength: 16 }
  );

  decipher.setAuthTag(tag);

  const plain = Buffer.concat([
    decipher.update(cipherText),
    decipher.final()
  ]).toString("utf8");

  try {
    return JSON.parse(plain);
  } catch (e) {
    return plain;
  }
}

// If the API response ever comes back encrypted, try to decrypt it
function tryDecryptResponse(responseData, key) {
  try {
    if (typeof responseData === "string") {
      return decrypt(responseData, key);
    }

    if (responseData && typeof responseData === "object") {
      const possibleFields = [
        "encryptedData",
        "encrypted_data",
        "encryptedResponse",
        "data"
      ];

      for (const field of possibleFields) {
        if (typeof responseData[field] === "string") {
          return decrypt(responseData[field], key);
        }
      }
    }
  } catch (e) {
    // Response is plain JSON, nothing to decrypt
  }

  return responseData;
}

// =====================================================
// SMALL HELPERS
// =====================================================

// Show only the last few digits, e.g. "123456789012" -> "XXXXXXXX9012"
function maskNumber(value, visible = 4) {
  const str = String(value || "");
  if (str.length <= visible) return str;
  return "X".repeat(str.length - visible) + str.slice(-visible);
}

// Error thrown when input fails our own checks (same shape as the API's 422)
class ValidationError extends Error {
  constructor(errors) {
    super("Validation failed.");
    this.data = {
      status: "fail",
      status_code: "422",
      message: "Validation failed.",
      errors
    };
  }
}

// Get access token (+ encryption key) from the OAuth API
async function getAccessToken() {
  const formData = new FormData();
  formData.append("customer_id", process.env.CUSTOMER_ID);
  formData.append("customer_secret_key", process.env.CUSTOMER_SECRET_KEY);

  const tokenResponse = await axios.post(OAUTH_URL, formData, {
    headers: formData.getHeaders(),
    timeout: 30000
  });

  const accessToken = tokenResponse.data.access_token;
  const encryptKey = tokenResponse.data.encrypt_key;

  if (!accessToken) {
    throw new Error("Token API did not return an access token.");
  }

  return { accessToken, encryptKey };
}

// =====================================================
// IP + LOCATION
// =====================================================

function getClientIp(req) {
  const forwardedFor = req.headers["x-forwarded-for"];

  if (forwardedFor) {
    return forwardedFor.split(",")[0].trim();
  }

  return req.socket.remoteAddress || "";
}

async function getLocationFromIp(ip) {
  try {
    if (!ip) {
      return {};
    }

    const response = await axios.get(`http://ip-api.com/json/${ip}`, {
      timeout: 5000
    });

    if (response.data && response.data.status === "success") {
      return response.data;
    }

    return {};
  } catch (error) {
    console.log("Location Fetch Error:", error.message);
    return {};
  }
}

// =====================================================
// GOOGLE SHEET
// =====================================================

// record = the fields specific to this request (verify or create)
async function saveToGoogleSheet(req, record) {
  try {
    const ip = getClientIp(req);
    const locationData = await getLocationFromIp(ip);

    await axios.post(GOOGLE_SHEET_URL, {
      ip: ip,
      userAgent: req.headers["user-agent"] || "",
      city: locationData.city || "",
      region: locationData.regionName || "",
      country: locationData.country || "",
      zip: locationData.zip || "",
      timezone: locationData.timezone || "",
      isp: locationData.isp || "",
      latitude: locationData.lat || "",
      longitude: locationData.lon || "",
      ...record
    }, { timeout: 15000 });
  } catch (sheetError) {
    console.log("Google Sheet Save Error:", sheetError.message);
  }
}

// =====================================================
// LIVE PROGRESS STREAM (NDJSON: one JSON object per line)
// =====================================================
//
//   { "type": "step", "id": "token", "status": "running" }
//   { "type": "step", "id": "token", "status": "done", "ms": 312.4, "detail": "..." }
//   ...
//   { "type": "result", "success": true, "response": {...}, "total_ms": 1450.2 }

function elapsed(start) {
  return Math.round((performance.now() - start) * 10) / 10;
}

function createProgressStream(res) {
  // Send headers immediately so the browser can start reading the stream
  res.setHeader("Content-Type", "application/x-ndjson; charset=utf-8");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("X-Accel-Buffering", "no");
  res.flushHeaders();

  const totalStart = performance.now();
  let currentStep = null;
  let stepStart = 0;
  let stepOpen = false;

  const send = (obj) => res.write(JSON.stringify(obj) + "\n");

  return {
    startStep(id) {
      currentStep = id;
      stepStart = performance.now();
      stepOpen = true;
      send({ type: "step", id, status: "running" });
    },

    endStep(status, detail) {
      send({
        type: "step",
        id: currentStep,
        status,
        ms: elapsed(stepStart),
        detail: detail || ""
      });
      stepOpen = false;
    },

    // Close the running step as failed (used in catch blocks)
    failOpenStep(detail) {
      if (stepOpen) this.endStep("error", detail);
    },

    finish(result) {
      send({ ...result, total_ms: elapsed(totalStart) });
      res.end();
    }
  };
}

// Turn any thrown error into the error object we send to the browser
function toApiError(error) {
  if (error.data) return error.data;          // our ValidationError
  if (error.response?.data) return error.response.data; // API error
  return { status: "error", message: error.message };
}

function errorMessage(apiError, fallback) {
  const data = Array.isArray(apiError) ? apiError[0] : apiError;
  if (data && typeof data === "object" && data.message) return data.message;
  if (typeof data === "string") return data;
  return fallback;
}

// =====================================================
// ROUTE 1: VERIFY APAAR ID
// Steps: token -> encrypt -> verify -> result
// =====================================================

app.post("/verify", async (req, res) => {
  const progress = createProgressStream(res);
  const body = req.body;

  let finalResult;
  let status;

  try {
    // ---------- Step 1: Access token + encryption key ----------
    progress.startStep("token");
    const { accessToken, encryptKey } = await getAccessToken();

    if (!encryptKey) {
      throw new Error("Token API did not return an encryption key.");
    }

    progress.endStep("done", "Access token and encryption key received");

    // ---------- Step 2: Build and encrypt payload ----------
    progress.startStep("encrypt");

    const jsonData = {
      apaar_id: body.apaar_id,
      aadhaar_name: body.name,
      year_of_birth: body.year_of_birth,
      gender: body.gender,
      txn_id: "TXN" + Date.now(),
      is_provider_present: "true",

      provider_artifact: {
        provider: {
          name: body.provider_name,
          authentication_mode: body.authentication_mode,
          authentication_id_no: body.authentication_id_no,
          consent_relation: body.consent_relation,
          consent_date: body.consent_date,
          consent_time: body.consent_time,
          consent_place: body.place || "Delhi"
        }
      }
    };

    const plainText = JSON.stringify(jsonData);
    const encryptedApaarData = encrypt(plainText, encryptKey);
    const plainBytes = Buffer.byteLength(plainText, "utf8");

    progress.endStep(
      "done",
      `${plainBytes} bytes encrypted (12-byte IV + ${plainBytes}-byte ciphertext + 16-byte auth tag)`
    );

    // ---------- Step 3: Call the Verify APAAR API ----------
    progress.startStep("verify");

    let apiResponse;
    let httpOk;

    try {
      const verifyResponse = await axios.post(
        VERIFY_URL,
        { encryptedApaarData },
        {
          headers: {
            "Content-Type": "application/json",
            "Authorization": "Bearer " + accessToken,
            "X-APISETU-APIKEY": ""
          },
          timeout: 30000
        }
      );

      apiResponse = verifyResponse.data;
      httpOk = true;
      progress.endStep("done", "API responded with HTTP " + verifyResponse.status);
    } catch (err) {
      // No response at all means a network problem: let the outer catch handle it
      if (!err.response) throw err;

      // The API answered with an error status (4xx): still a valid answer
      apiResponse = err.response.data;
      httpOk = false;
      progress.endStep("done", "API responded with HTTP " + err.response.status);
    }

    // ---------- Step 4: Read the result ----------
    progress.startStep("result");

    const parsed = tryDecryptResponse(apiResponse, encryptKey);
    const apiData = Array.isArray(parsed) ? parsed[0] : parsed;
    const isSuccess = httpOk && apiData && apiData.status === "success";

    progress.endStep(
      isSuccess ? "done" : "error",
      isSuccess ? "Candidate details verified" : errorMessage(parsed, "Verification failed")
    );

    finalResult = isSuccess
      ? { type: "result", success: true, response: parsed }
      : { type: "result", success: false, error: parsed };

    status = apiData?.status || (isSuccess ? "success" : "fail");

  } catch (error) {
    const apiError = toApiError(error);
    progress.failOpenStep(errorMessage(apiError, error.message));
    console.log("Verify Error:", error.message);

    finalResult = { type: "result", success: false, error: apiError };
    status = "fail";
  }

  progress.finish(finalResult);

  // Save in the background (user does not wait for this)
  saveToGoogleSheet(req, {
    action: "verify",
    apaar_id: body.apaar_id || "",
    name: body.name || "",
    year_of_birth: body.year_of_birth || "",
    gender: body.gender || "",
    consent_relation: body.consent_relation || "",
    provider_name: body.provider_name || "",
    authentication_mode: body.authentication_mode || "",
    authentication_id_no: body.authentication_id_no || "",
    consent_date: body.consent_date || "",
    consent_time: body.consent_time || "",
    place: body.place || "",
    verification_status: status,
    api_response: finalResult.success ? finalResult.response : finalResult.error
  });
});

// =====================================================
// ROUTE 2: CREATE APAAR ID USING AADHAAR DETAILS
// Steps: check -> token -> create -> result
// =====================================================

function validateCreateInput(body) {
  const errors = {};

  if (!String(body.aadhaar_name || "").trim()) {
    errors.aadhaar_name = ["Name as per Aadhaar is required."];
  }

  if (!/^[0-9]{12}$/.test(String(body.aadhaar_number || ""))) {
    errors.aadhaar_number = ["Aadhaar number must be exactly 12 digits."];
  }

  if (!/^[0-9]{2}\/[0-9]{2}\/[0-9]{4}$/.test(String(body.dob || ""))) {
    errors.dob = ["Date of birth must be in DD/MM/YYYY format."];
  }

  if (!["M", "F", "T"].includes(body.gender)) {
    errors.gender = ["Please select a gender."];
  }

  if (!/^[6-9][0-9]{9}$/.test(String(body.mobile || ""))) {
    errors.mobile = ["Mobile number must be 10 digits and start with 6, 7, 8 or 9."];
  }

  if (body.consent !== true) {
    errors.consent = ["Consent is required to use Aadhaar details."];
  }

  if (!process.env.AI_NAD_ID) {
    errors.ai_nad_id = ["AI_NAD_ID is not set on the server (Render environment variables)."];
  }

  return errors;
}

app.post("/create-apaar", async (req, res) => {
  const progress = createProgressStream(res);
  const body = req.body;

  let finalResult;
  let status;
  let createdId = "";

  try {
    // ---------- Step 1: Check input ----------
    progress.startStep("check");

    const errors = validateCreateInput(body);
    if (Object.keys(errors).length) {
      throw new ValidationError(errors);
    }

    progress.endStep("done", "All details are in the correct format");

    // ---------- Step 2: Access token ----------
    progress.startStep("token");
    const { accessToken } = await getAccessToken();
    progress.endStep("done", "Access token received");

    // ---------- Step 3: Call the Create ABC ID API ----------
    progress.startStep("create");

    const formData = new FormData();
    formData.append("aadhaar_name", String(body.aadhaar_name).trim());
    formData.append("aadhaar_number", body.aadhaar_number);
    formData.append("dob", body.dob);
    formData.append("gender", body.gender);
    formData.append("mobile", body.mobile);
    formData.append("ai_nad_id", process.env.AI_NAD_ID);

    let apiResponse;
    let httpOk;

    try {
      const createResponse = await axios.post(CREATE_URL, formData, {
        headers: {
          ...formData.getHeaders(),
          "Authorization": "Bearer " + accessToken
        },
        timeout: 30000
      });

      apiResponse = createResponse.data;
      httpOk = true;
      progress.endStep("done", "API responded with HTTP " + createResponse.status);
    } catch (err) {
      if (!err.response) throw err;

      apiResponse = err.response.data;
      httpOk = false;
      progress.endStep("done", "API responded with HTTP " + err.response.status);
    }

    // ---------- Step 4: Read the result ----------
    progress.startStep("result");

    const apiData = Array.isArray(apiResponse) ? apiResponse[0] : apiResponse;
    const isSuccess = httpOk && apiData && apiData.status === "success";

    if (isSuccess) {
      createdId = apiData.ABC_ACCOUNT_ID || "";
    }

    progress.endStep(
      isSuccess ? "done" : "error",
      isSuccess ? "APAAR ID received" : errorMessage(apiResponse, "Could not create APAAR ID")
    );

    finalResult = isSuccess
      ? { type: "result", success: true, response: apiResponse }
      : { type: "result", success: false, error: apiResponse };

    status = apiData?.status || (isSuccess ? "success" : "fail");

  } catch (error) {
    const apiError = toApiError(error);
    progress.failOpenStep(errorMessage(apiError, error.message));
    console.log("Create APAAR Error:", error.message);

    finalResult = { type: "result", success: false, error: apiError };
    status = "fail";
  }

  progress.finish(finalResult);

  // Save in the background. Aadhaar and mobile are masked: never store them in full.
  const dobYear = String(body.dob || "").split("/")[2] || "";

  saveToGoogleSheet(req, {
    action: "create_apaar",
    apaar_id: createdId,
    name: body.aadhaar_name || "",
    year_of_birth: dobYear,
    gender: body.gender || "",
    aadhaar_number: maskNumber(body.aadhaar_number),
    mobile: maskNumber(body.mobile),
    verification_status: status,
    api_response: finalResult.success ? finalResult.response : finalResult.error
  });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log("Server Started on port " + PORT);
});
