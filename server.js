const express = require("express");
const axios = require("axios");
const FormData = require("form-data");
const crypto = require("crypto");

const app = express();

app.use(express.json());

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

app.post("/verify", async (req, res) => {

  try {

    // =========================
    // STEP 1 - TOKEN API
    // =========================

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

    const accessToken =
      tokenResponse.data.access_token;

    const encryptKey =
      tokenResponse.data.encrypt_key;

    // =========================
    // STEP 2 - CREATE JSON
    // =========================

    const now = new Date();

    const currentDate =
      now.toLocaleDateString("en-GB");

    const currentTime =
      now.toLocaleTimeString("en-GB");

    const txnId =
      "TXN" + Date.now();

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

          authentication_id_no:req.body.authentication_id_no,

          consent_relation: req.body.consent_relation,

          consent_date: req.body.consent_date,

          consent_time: req.body.consent_time,

          consent_place: req.body.place || "Delhi"

        }
      }
    };

    // =========================
    // STEP 3 - ENCRYPT DATA
    // =========================

    const encryptedApaarData =
      encrypt(
        JSON.stringify(jsonData),
        encryptKey
      );

    // =========================
    // STEP 4 - VERIFY APAAR
    // =========================

    const verifyResponse =
      await axios.post(

        "https://nadapi.digilocker.gov.in/v1/VerifyApaar",

        {
          encryptedApaarData
        },

        {
          headers: {

            "Content-Type":
              "application/json",

            "Authorization":
              "Bearer " + accessToken,

            "X-APISETU-APIKEY": ""
          }
        }
      );
    // =========================
// SAVE TO GOOGLE SHEET
// =========================

try {

  await axios.post(
    "https://script.google.com/macros/s/AKfycbzee7qiMQT2CcBXixoDhNLg6uEmnVz1acOCroBc70QQAJnuia5Eo3HvcK23Mio98jwK/exec",

    {

      ip:
        req.headers["x-forwarded-for"]
        || req.socket.remoteAddress,

      userAgent:
        req.headers["user-agent"],

      apaar_id:
        req.body.apaar_id,

      name:
        req.body.name,

      year_of_birth:
        req.body.year_of_birth,

      gender:
        req.body.gender,

      consent_relation:
        req.body.consent_relation,

      provider_name:
        req.body.provider_name,

      authentication_mode:
        req.body.authentication_mode,

      authentication_id_no:
        req.body.authentication_id_no,

      consent_date:
        req.body.consent_date,

      consent_time:
        req.body.consent_time,

      place:
        req.body.place,

      verification_status:
        verifyResponse.data?.status || "",

      api_response:
        verifyResponse.data

    }

  );

}
catch(sheetError) {

  console.log(
    "Google Sheet Save Error:",
    sheetError.message
  );

}

    // =========================
    // FINAL RESPONSE
    // =========================

    res.json({
      success: true,
      response:
        verifyResponse.data
    });

  }
  catch (error) {

    res.json({

      success: false,

      error:
        error.response?.data
        || error.message

    });
  }

});

app.listen(3000, () => {
  console.log("Server Started");
});
