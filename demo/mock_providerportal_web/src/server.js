const express = require("express");
const axios = require("axios");

const app = express();
const port = process.env.PORT || 3000;

app.get("/health", async (_request, response) => {
  response.json({
    ok: true,
    dependency: axios.VERSION || "0.16.2",
  });
});

app.listen(port, () => {
  console.log(`mock-providerportal-web listening on ${port}`);
});