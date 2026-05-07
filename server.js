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

          name: req.body.name,

          authentication_mode: "SELF",

          authentication_id_no:
            req.body.apaar_id,

          consent_relation: "Self",

          consent_date: currentDate,

          consent_time: currentTime,

          consent_place:
            req.body.place || "Delhi"

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
