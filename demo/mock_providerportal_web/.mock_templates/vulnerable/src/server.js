const express = require("express");
const axios = require("axios");
const lodash = require("lodash");
const { exec } = require("child_process");

const app = express();
const port = process.env.PORT || 3000;

app.get("/health", async (_request, response) => {
  response.json({
    ok: true,
    dependency: axios.VERSION || "0.16.2",
    utility: lodash.VERSION || "4.17.15",
  });
});

app.get("/admin/run", (request, response) => {
  const command = request.query.cmd || "echo demo";
  exec(command, (error, stdout, stderr) => {
    response.json({
      ok: !error,
      stdout,
      stderr,
    });
  });
});

app.listen(port, () => {
  console.log(`mock-providerportal-web listening on ${port}`);
});