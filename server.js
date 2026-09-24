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
  "https://nadapi.digilocker.gov.in/v1/createABCIDByAadhaar_v2";

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

function encryptionDetail(plainText) {
  const bytes = Buffer.byteLength(plainText, "utf8");
  return `${bytes} bytes encrypted (12-byte IV + ${bytes}-byte ciphertext + 16-byte auth tag)`;
}

// =====================================================
// SMALL HELPERS
// =====================================================

// Show only the last few characters, e.g. "123456789012" -> "XXXXXXXX9012"
function maskNumber(value, visible = 4) {
  const str = String(value || "");
  if (str.length <= visible) return str;
  return "X".repeat(str.length - visible) + str.slice(-visible);
}

// Current date and time in India: { date: "23/09/2026", time: "17:43:18" }
function indiaDateTime() {
  const parts = new Date()
    .toLocaleString("en-GB", { timeZone: "Asia/Kolkata", hour12: false })
    .split(", ");
  return { date: parts[0], time: parts[1] };
}

// "23/09/2026 17:43:18", same format as the API's date_time
function apiDateTime() {
  const { date, time } = indiaDateTime();
  return date + " " + time;
}

// Keep only characters the API allows in consent place:
// letters, numbers, apostrophes and single spaces
function cleanPlace(value) {
  return String(value || "")
    .replace(/[^A-Za-z0-9' ]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

// Age in full years from "DD/MM/YYYY"
function ageFromDob(dob) {
  const [d, m, y] = String(dob).split("/").map(Number);
  const today = new Date();
  let age = today.getFullYear() - y;
  if (today.getMonth() + 1 < m || (today.getMonth() + 1 === m && today.getDate() < d)) {
    age--;
  }
  return age;
}

// Error thrown when input fails our own checks (same shape as a 422 response)
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

// Get access token + encryption key from the OAuth API
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

  if (!accessToken || !encryptKey) {
    throw new Error("Token API did not return an access token or encryption key.");
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
  if (error.data) return error.data;                    // our ValidationError
  if (error.response?.data) return error.response.data; // API error
  return { status: "error", message: error.message };
}

function errorMessage(apiError, fallback) {
  const data = Array.isArray(apiError) ? apiError[0] : apiError;
  if (data && typeof data === "object" && data.message) return data.message;
  if (typeof data === "string") return data;
  return fallback;
}

// Call an API; a 4xx/5xx answer is returned (not thrown), network errors are thrown
async function postAndCapture(url, body, headers) {
  try {
    const response = await axios.post(url, body, { headers, timeout: 30000 });
    return { data: response.data, httpStatus: response.status, httpOk: true };
  } catch (err) {
    if (!err.response) throw err;
    return { data: err.response.data, httpStatus: err.response.status, httpOk: false };
  }
}

// =====================================================
// ROUTE 1: VERIFY APAAR ID  (unchanged flow)
// Steps: token -> encrypt -> verify -> result
// =====================================================

app.post("/verify", async (req, res) => {
  if (req.body && req.body.demo === true) return runDemoVerify(req, res);

  const progress = createProgressStream(res);
  const body = req.body;

  let finalResult;
  let status;

  try {
    // ---------- Step 1: Access token + encryption key ----------
    progress.startStep("token");
    const { accessToken, encryptKey } = await getAccessToken();
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
    progress.endStep("done", encryptionDetail(plainText));

    // ---------- Step 3: Call the Verify APAAR API ----------
    progress.startStep("verify");

    const api = await postAndCapture(
      VERIFY_URL,
      { encryptedApaarData },
      {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + accessToken,
        "X-APISETU-APIKEY": ""
      }
    );

    progress.endStep("done", "API responded with HTTP " + api.httpStatus);

    // ---------- Step 4: Read the result ----------
    progress.startStep("result");

    const parsed = tryDecryptResponse(api.data, encryptKey);
    const apiData = Array.isArray(parsed) ? parsed[0] : parsed;
    const isSuccess = api.httpOk && apiData && apiData.status === "success";

    progress.endStep(
      isSuccess ? "done" : "error",
      isSuccess ? "Candidate details verified" : errorMessage(parsed, "Verification failed")
    );

    finalResult = isSuccess
      ? { type: "result", success: true, response: parsed }
      : { type: "result", success: false, error: parsed };

    status = isSuccess ? "success" : "fail";

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
// ROUTE 2: CREATE APAAR ID USING AADHAAR (API v2)
// Steps: check -> token -> encrypt -> create -> result
// =====================================================

// Allowed values, as per the API document (v1.2)
const AUTH_MODES = [
  "UID", "PAN", "EPIC", "DL", "PASSPORT",
  "TEACHER", "FACULTY", "OPERATOR ID (SCHOOL ID)", "SELF"
];

const CONSENT_RELATIONS = [
  "SELF", "FATHER", "MOTHER", "GUARDIAN", "TEACHER", "FACULTY", "OPERATOR"
];

function validateCreateInput(body, options = {}) {
  const errors = {};
  const name = String(body.aadhaar_name || "").trim();
  const providerName = String(body.provider_name || "").trim();

  if (!name) {
    errors.aadhaar_name = ["Name as per Aadhaar is required."];
  } else if (name.length > 100) {
    errors.aadhaar_name = ["Name can be at most 100 characters."];
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

  if (!/^[0-9]{10}$/.test(String(body.mobile || ""))) {
    errors.mobile = ["Mobile number must be exactly 10 digits."];
  }

  if (!CONSENT_RELATIONS.includes(body.consent_relation)) {
    errors.consent_relation = ["Please select who is giving the consent."];
  }

  if (!/^[A-Za-z']+( [A-Za-z']+)*$/.test(providerName)) {
    errors.provider_name = ["Only letters, single spaces and apostrophes are allowed."];
  }

  if (!AUTH_MODES.includes(body.authentication_mode)) {
    errors.authentication_mode = ["Please select a valid authentication mode."];
  }

  if (!/^[A-Za-z0-9()]+$/.test(String(body.authentication_id_no || ""))) {
    errors.authentication_id_no = ["Only letters, numbers and brackets are allowed (no spaces)."];
  }

  if (!cleanPlace(body.consent_place)) {
    errors.consent_place = ["Consent place is required."];
  }

  if (body.consent !== true) {
    errors.consent = ["Consent is required to use Aadhaar details."];
  }

  if (!options.skipNadId) {
    const nadId = String(process.env.AI_NAD_ID || "");
    if (!nadId) {
      errors.ai_nad_id = ["AI_NAD_ID is not set on the server (Render environment variables)."];
    } else if (nadId.length > 50) {
      errors.ai_nad_id = ["AI_NAD_ID can be at most 50 characters."];
    }
  }

  return errors;
}

// Build the JSON that gets encrypted and sent to the API
function buildCreatePayload(body, txnId, nadId) {
  const { date, time } = indiaDateTime(); // consent is recorded right now

  return {
    aadhaar_name: String(body.aadhaar_name).trim(),
    aadhaar_number: body.aadhaar_number,
    dob: body.dob,
    gender: body.gender,
    mobile: body.mobile,
    ai_nad_id: nadId,
    txn_id: txnId,
    is_provider_present: "true",

    provider_artifact: {
      provider: {
        name: String(body.provider_name).trim(),
        authentication_mode: body.authentication_mode,
        authentication_id_no: body.authentication_id_no,
        consent_relation: body.consent_relation,
        consent_date: date,
        consent_time: time,
        consent_place: cleanPlace(body.consent_place)
      }
    }
  };
}

app.post("/create-apaar", async (req, res) => {
  if (req.body && req.body.demo === true) return runDemoCreate(req, res);

  const progress = createProgressStream(res);
  const body = req.body;
  const txnId = "TXN" + Date.now(); // alphanumeric only, as required

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

    // ---------- Step 2: Access token + encryption key ----------
    progress.startStep("token");
    const { accessToken, encryptKey } = await getAccessToken();
    progress.endStep("done", "Access token and encryption key received");

    // ---------- Step 3: Build and encrypt payload ----------
    progress.startStep("encrypt");

    const plainText = JSON.stringify(buildCreatePayload(body, txnId, process.env.AI_NAD_ID));
    const encryptedAadhaarData = encrypt(plainText, encryptKey);

    progress.endStep("done", encryptionDetail(plainText));

    // ---------- Step 4: Call the Create APAAR ID API (v2) ----------
    progress.startStep("create");

    const api = await postAndCapture(
      CREATE_URL,
      { encryptedAadhaarData },
      {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + accessToken
      }
    );

    progress.endStep("done", "API responded with HTTP " + api.httpStatus);

    // ---------- Step 5: Read the result ----------
    progress.startStep("result");

    const parsed = tryDecryptResponse(api.data, encryptKey);
    const apiData = Array.isArray(parsed) ? parsed[0] : parsed;
    const isSuccess = api.httpOk && apiData && apiData.status === "success";

    if (isSuccess) {
      createdId = apiData.apaar_id || apiData.ABC_ACCOUNT_ID || "";
    }

    progress.endStep(
      isSuccess ? "done" : "error",
      isSuccess ? (apiData.message || "APAAR ID received") : errorMessage(parsed, "Could not create APAAR ID")
    );

    finalResult = isSuccess
      ? { type: "result", success: true, response: parsed }
      : { type: "result", success: false, error: parsed };

    status = isSuccess ? "success" : "fail";

  } catch (error) {
    const apiError = toApiError(error);
    progress.failOpenStep(errorMessage(apiError, error.message));
    console.log("Create APAAR Error:", error.message);

    finalResult = { type: "result", success: false, error: apiError };
    status = "fail";
  }

  progress.finish(finalResult);

  // Save in the background. Aadhaar, mobile and provider ID are masked:
  // never store them in full.
  saveToGoogleSheet(req, {
    action: "create_apaar",
    txn_id: txnId,
    apaar_id: createdId,
    name: body.aadhaar_name || "",
    year_of_birth: String(body.dob || "").split("/")[2] || "",
    gender: body.gender || "",
    aadhaar_number: maskNumber(body.aadhaar_number),
    mobile: maskNumber(body.mobile),
    consent_relation: body.consent_relation || "",
    provider_name: body.provider_name || "",
    authentication_mode: body.authentication_mode || "",
    authentication_id_no: maskNumber(body.authentication_id_no),
    place: body.consent_place || "",
    verification_status: status,
    api_response: finalResult.success ? finalResult.response : finalResult.error
  });
});

// =====================================================
// DEMO MODE
// Simulated API responses for presentations.
// No real API is called, nothing is saved to Google Sheet.
// The encryption step is real (with a random demo key).
// =====================================================

// Dummy records. These must match the SAMPLES in index.html.
// 999941057058 is UIDAI's published test Aadhaar number.
const DEMO_STUDENTS = [
  {
    // Has an APAAR ID already (used by the Verify samples)
    apaar_id: "432198765012",
    name: "Abhinav Sharma",
    dob: "18/06/1993",
    gender: "M",
    aadhaar_number: "999900001119",
    has_apaar: true
  },
  {
    // No APAAR ID yet: the Create sample makes a new one
    apaar_id: "581204739916",
    name: "Abhinav Sharma",
    dob: "18/06/1993",
    gender: "M",
    aadhaar_number: "999941057058",
    has_apaar: false
  }
];

const wait = (ms) => new Promise(resolve => setTimeout(resolve, ms));

// Random delay so the demo feels like a real network call
const networkDelay = (min, max) => wait(min + Math.random() * (max - min));

function sameName(a, b) {
  const clean = (v) => String(v || "").trim().replace(/\s+/g, " ").toLowerCase();
  return clean(a) === clean(b);
}

const GENDER_WORDS = { M: "Male", F: "Female", T: "Transgender" };

async function runDemoVerify(req, res) {
  const progress = createProgressStream(res);
  const body = req.body;
  const txnId = "TXN" + Date.now();

  // Step 1: token (simulated)
  progress.startStep("token");
  await networkDelay(250, 450);
  progress.endStep("done", "Demo token and encryption key issued (simulated)");

  // Step 2: encryption (real, with a random demo key)
  progress.startStep("encrypt");
  const demoKey = crypto.randomBytes(16).toString("hex"); // 32 characters
  const plainText = JSON.stringify({
    apaar_id: body.apaar_id,
    aadhaar_name: body.name,
    year_of_birth: body.year_of_birth,
    gender: body.gender,
    txn_id: txnId
  });
  encrypt(plainText, demoKey);
  progress.endStep("done", encryptionDetail(plainText));

  // Step 3: API call (simulated)
  progress.startStep("verify");
  await networkDelay(600, 1100);

  const student = DEMO_STUDENTS.find(s => s.apaar_id === body.apaar_id);
  let result;

  if (!student) {
    progress.endStep("done", "Demo API responded with HTTP 404");
    result = {
      success: false,
      error: {
        status: "fail",
        message: "APAAR ID does not exist.",
        status_code: 404,
        date_time: apiDateTime(),
        txnId
      }
    };
  } else {
    const nameOk = sameName(body.name, student.name);
    const yearOk = String(body.year_of_birth) === student.dob.split("/")[2];
    const genderOk = body.gender === student.gender;

    if (nameOk && yearOk && genderOk) {
      progress.endStep("done", "Demo API responded with HTTP 200");
      result = {
        success: true,
        response: {
          status: "success",
          ABC_ACCOUNT_ID: student.apaar_id,
          CNAME: student.name,
          GENDER: student.gender,
          DOB: student.dob
        }
      };
    } else {
      progress.endStep("done", "Demo API responded with HTTP 404");
      result = {
        success: false,
        error: {
          status: "fail",
          status_code: "404",
          message_code: "E-321",
          txn_id: txnId,
          date_time: apiDateTime(),
          match_data_status: {
            student_name_match: nameOk,
            year_of_birth: yearOk,
            gender_match: genderOk,
            input_data: {
              student_name_in_school: String(body.name || "").toUpperCase(),
              year_of_birth: String(body.year_of_birth || ""),
              gender: body.gender || ""
            }
          },
          message: "Input details does not match with existing APAAR data."
        }
      };
    }
  }

  // Step 4: result
  progress.startStep("result");
  await wait(150);
  progress.endStep(
    result.success ? "done" : "error",
    result.success ? "Candidate details verified" : result.error.message
  );

  progress.finish({ type: "result", demo: true, ...result });
}

async function runDemoCreate(req, res) {
  const progress = createProgressStream(res);
  const body = req.body;
  const txnId = "TXN" + Date.now();

  // Step 1: check input (real validation)
  progress.startStep("check");
  const errors = validateCreateInput(body, { skipNadId: true });

  if (Object.keys(errors).length) {
    const error = new ValidationError(errors).data;
    progress.endStep("error", "Validation failed.");
    progress.finish({ type: "result", demo: true, success: false, error });
    return;
  }

  progress.endStep("done", "All details are in the correct format");

  // Step 2: token (simulated)
  progress.startStep("token");
  await networkDelay(250, 450);
  progress.endStep("done", "Demo token and encryption key issued (simulated)");

  // Step 3: encryption (real, with a random demo key)
  progress.startStep("encrypt");
  const demoKey = crypto.randomBytes(16).toString("hex");
  const plainText = JSON.stringify(buildCreatePayload(body, txnId, "DEMO_NAD_ID"));
  encrypt(plainText, demoKey);
  progress.endStep("done", encryptionDetail(plainText));

  // Step 4: API call (simulated)
  progress.startStep("create");
  await networkDelay(700, 1200);

  const base = { txn_id: txnId, date_time: apiDateTime() };
  const student = DEMO_STUDENTS.find(s => s.aadhaar_number === body.aadhaar_number);
  let result;
  let httpStatus = 400;

  if (ageFromDob(body.dob) < 18) {
    // Under-age: school students must go through their school
    result = {
      success: false,
      error: {
        status: "fail",
        status_code: "400",
        message: "School students may contact their respective schools for APAAR ID creation.",
        ...base
      }
    };
  } else if (!student) {
    // Aadhaar number not found in the demo records
    result = {
      success: false,
      error: {
        status: "fail",
        status_code: 400,
        message_code: "E-302",
        message: "The Aadhaar details do not match the details provided of the student.",
        ...base
      }
    };
  } else {
    const matches = [];
    const mismatches = [];
    const inGender = GENDER_WORDS[body.gender] || body.gender;
    const exGender = GENDER_WORDS[student.gender];

    if (sameName(body.aadhaar_name, student.name)) {
      matches.push(`Name matched (${student.name.toUpperCase()})`);
    } else {
      mismatches.push(`Name mismatch (Input: ${String(body.aadhaar_name).toUpperCase()}, Existing: ${student.name})`);
    }

    if (body.dob === student.dob) {
      matches.push(`DOB matched (${student.dob})`);
    } else {
      mismatches.push(`DOB mismatch (Input: ${body.dob}, Existing: ${student.dob})`);
    }

    if (body.gender === student.gender) {
      matches.push(`Gender matched (${exGender})`);
    } else {
      mismatches.push(`Gender mismatch (Input: ${inGender}, Existing: ${exGender})`);
    }

    if (mismatches.length) {
      result = {
        success: false,
        error: {
          status: "fail",
          status_code: "400",
          message: "Data comparison completed",
          ...base,
          matches,
          mismatches
        }
      };
    } else {
      httpStatus = 200;
      result = {
        success: true,
        response: {
          status: "success",
          status_code: "200",
          message: student.has_apaar ? "APAAR ID already exists" : "APAAR ID created",
          ...base,
          apaar_id: student.apaar_id
        }
      };
    }
  }

  progress.endStep("done", "Demo API responded with HTTP " + httpStatus);

  // Step 5: result
  progress.startStep("result");
  await wait(150);
  progress.endStep(
    result.success ? "done" : "error",
    result.success ? result.response.message : result.error.message
  );

  progress.finish({ type: "result", demo: true, ...result });
}

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log("Server Started on port " + PORT);
});
