import express from "express";
const app = express();
app.use(express.json());

const fakeSecrets = `
AWS Key: AKIAABCDEFGHIJKLMNOP
AWS Secret: AKIAABCDEFGHIJKLMNOP
OpenAI: sk-test_abc123XYZ
Email: alice@example.com
SSN: 123-45-6789
`;

app.post("/api/v1/llm/query", (req, res) => {
  const { prompt, leak } = req.body || {};

  res.json({
    echoedPrompt: prompt,
    modelResponse:
      "Response from LLM.\n" + (leak == "true" ? fakeSecrets : Date.now()),
  });
});

app.get("/", (req, res) => res.send("OK"));
app.listen(3333, () => console.log("Backend listening on 3333"));
