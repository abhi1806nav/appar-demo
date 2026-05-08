const express = require("express");
const axios = require("axios");
const FormData = require("form-data");
const crypto = require("crypto");

const app = express();

app.use(express.json());

const GOOGLE_SHEET_URL =
  "https://script.google.com/macros/s/AKfycbzee7qiMQT2CcBXixoDhNLg6uEmnVz1acOCroBc70QQAJnuia5Eo3HvcK23Mio98jwK/exec";

app.get("/", (req, res) => {
  res.sendFile(__dirname + "/index.html");
});

function encrypt(data, key) {
  const cipher = crypto.createCipheriv(
    "aes-256-ecb",
    Buffer.from(key, "utf8"),
    null
  );

  cipher.setAutoPadding(true);

  let encrypted = cipher.update(data, "utf8", "base64");
  encrypted += cipher.final("base64");

  return encrypted;
}

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

    const response = await axios.get(
      `http://ip-api.com/json/${ip}`
    );

    if (response.data && response.data.status === "success") {
      return response.data;
    }

    return {};
  } catch (error) {
    console.log("Location Fetch Error:", error.message);
    return {};
  }
}

async function saveToGoogleSheet(req, apiResponse, verificationStatus) {
  try {
    const ip = getClientIp(req);
    const locationData = await getLocationFromIp(ip);

    await axios.post(GOOGLE_SHEET_URL, {
      ip: ip,

      userAgent:
        req.headers["user-agent"] || "",

      city:
        locationData.city || "",

      region:
        locationData.regionName || "",

      country:
        locationData.country || "",

      zip:
        locationData.zip || "",

      timezone:
        locationData.timezone || "",

      isp:
        locationData.isp || "",

      latitude:
        locationData.lat || "",

      longitude:
        locationData.lon || "",

      apaar_id:
        req.body.apaar_id || "",

      name:
        req.body.name || "",

      year_of_birth:
        req.body.year_of_birth || "",

      gender:
        req.body.gender || "",

      consent_relation:
        req.body.consent_relation || "",

      provider_name:
        req.body.provider_name || "",

      authentication_mode:
        req.body.authentication_mode || "",

      authentication_id_no:
        req.body.authentication_id_no || "",

      consent_date:
        req.body.consent_date || "",

      consent_time:
        req.body.consent_time || "",

      place:
        req.body.place || "",

      verification_status:
        verificationStatus || "",

      api_response:
        apiResponse || {}
    });

  } catch (sheetError) {
    console.log("Google Sheet Save Error:", sheetError.message);
  }
}

app.post("/verify", async (req, res) => {
  try {
    const formData = new FormData();

    formData.append(
      "customer_id",
      process.env.CUSTOMER_ID
    );

    formData.append(
      "customer_secret_key",
      process.env.CUSTOMER_SECRET_KEY
    );

    const tokenResponse = await axios.post(
      "https://nadapi.digilocker.gov.in/v1/oauth",
      formData,
      {
        headers: formData.getHeaders()
      }
    );

    const accessToken = tokenResponse.data.access_token;
    const encryptKey = tokenResponse.data.encrypt_key;

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

    const encryptedApaarData = encrypt(
      JSON.stringify(jsonData),
      encryptKey
    );

    const verifyResponse = await axios.post(
      "https://nadapi.digilocker.gov.in/v1/VerifyApaar",
      {
        encryptedApaarData
      },
      {
        headers: {
          "Content-Type": "application/json",
          "Authorization": "Bearer " + accessToken,
          "X-APISETU-APIKEY": ""
        }
      }
    );

    const apiResponse = verifyResponse.data;
    const apiData = Array.isArray(apiResponse)
      ? apiResponse[0]
      : apiResponse;

    await saveToGoogleSheet(
      req,
      apiResponse,
      apiData?.status || "success"
    );

    res.json({
      success: true,
      response: apiResponse
    });

  } catch (error) {
    const apiError =
      error.response?.data || {
        status: "error",
        message: error.message
      };

    const apiData = Array.isArray(apiError)
      ? apiError[0]
      : apiError;

    await saveToGoogleSheet(
      req,
      apiError,
      apiData?.status || "fail"
    );

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
