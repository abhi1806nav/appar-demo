const express = require("express");
const axios = require("axios");
const FormData = require("form-data");
const crypto = require("crypto");

const app = express();

app.use(express.json());

const GOOGLE_SHEET_URL =
  "https://script.google.com/macros/s/AKfycbzee7qiMQT2CcBXixoDhNLg6uEmnVz1acOCroBc70QQAJnuia5Eo3HvcK23Mio98jwK/exec";

// Agar API ka URL badal gaya ho, to Render ke Environment me VERIFY_URL daal dena
const VERIFY_URL =
  process.env.VERIFY_URL ||
  "https://nadapi.digilocker.gov.in/v1/VerifyApaar";

app.get("/", (req, res) => {
  res.sendFile(__dirname + "/index.html");
});

// =====================================================
// ENCRYPTION (AES-256-GCM) - PHP code ke bilkul same
// =====================================================

// PHP ki tarah key ko exactly 32 bytes ka banao
// (chhoti key -> null bytes se pad, lambi key -> 32 par cut)
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

// Agar API response encrypted string me aaye, to use decrypt karne ki koshish
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
    console.log("Response decrypt nahi hua (shayad plain JSON hai):", e.message);
  }

  return responseData;
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

    const response = await axios.get(`http://ip-api.com/json/${ip}`);

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

async function saveToGoogleSheet(req, apiResponse, verificationStatus) {
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

      apaar_id: req.body.apaar_id || "",
      name: req.body.name || "",
      year_of_birth: req.body.year_of_birth || "",
      gender: req.body.gender || "",
      consent_relation: req.body.consent_relation || "",
      provider_name: req.body.provider_name || "",
      authentication_mode: req.body.authentication_mode || "",
      authentication_id_no: req.body.authentication_id_no || "",
      consent_date: req.body.consent_date || "",
      consent_time: req.body.consent_time || "",
      place: req.body.place || "",

      verification_status: verificationStatus || "",
      api_response: apiResponse || {}
    });
  } catch (sheetError) {
    console.log("Google Sheet Save Error:", sheetError.message);
  }
}

// =====================================================
// VERIFY ROUTE
// =====================================================

app.post("/verify", async (req, res) => {
  try {
    // ---------- Step 1: Token + Encrypt Key ----------
    const formData = new FormData();
    formData.append("customer_id", process.env.CUSTOMER_ID);
    formData.append("customer_secret_key", process.env.CUSTOMER_SECRET_KEY);

    const tokenResponse = await axios.post(
      "https://nadapi.digilocker.gov.in/v1/oauth",
      formData,
      { headers: formData.getHeaders() }
    );

    const accessToken = tokenResponse.data.access_token;
    const encryptKey = tokenResponse.data.encrypt_key;

    console.log(
      "Token mila. Encrypt key length:",
      encryptKey ? String(encryptKey).length : 0
    );

    // ---------- Step 2: Naya payload format ----------
    const txnId = "TXN" + Date.now();

const jsonData = {
  apaar_id: req.body.apaar_id,
  aadhaar_name: req.body.name,
  year_of_birth: req.body.year_of_birth,
  gender: req.body.gender,
  txn_id: txnId,
  is_provider_present: "true",

  provider_artifact: {
    provider: {
      name: req.body.provider_name,
      authentication_mode: req.body.authentication_mode,
      authentication_id_no: req.body.authentication_id_no,
      consent_relation: req.body.consent_relation,
      consent_date: req.body.consent_date,
      consent_time: req.body.consent_time,
      consent_place: req.body.place || "Delhi"
    }
  }
};

    console.log("Payload (encrypt se pehle):", jsonData);

    // ---------- Step 3: AES-256-GCM encryption ----------
    const encryptedApaarData = encrypt(JSON.stringify(jsonData), encryptKey);

    // ---------- Step 4: Verify API call ----------
    const verifyResponse = await axios.post(
      VERIFY_URL,
      { encryptedApaarData },
      {
        headers: {
          "Content-Type": "application/json",
          "Authorization": "Bearer " + accessToken,
          "X-APISETU-APIKEY": ""
        }
      }
    );

    console.log("API Raw Response:", JSON.stringify(verifyResponse.data));

    const apiResponse = tryDecryptResponse(verifyResponse.data, encryptKey);

    const apiData = Array.isArray(apiResponse) ? apiResponse[0] : apiResponse;

    await saveToGoogleSheet(req, apiResponse, apiData?.status || "success");

    res.json({
      success: true,
      response: apiResponse
    });
  } catch (error) {
    const apiError = error.response?.data || {
      status: "error",
      message: error.message
    };

    console.log("API Error:", JSON.stringify(apiError));

    const apiData = Array.isArray(apiError) ? apiError[0] : apiError;

    await saveToGoogleSheet(req, apiError, apiData?.status || "fail");

    res.json({
      success: false,
      error: apiError
    });
  }
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log("Server Started on port " + PORT);
});
