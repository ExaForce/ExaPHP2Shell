# ExaPHP2Shell

A static frontend on S3 plus a small Lambda that does the  actual scanning. S3 alone can't read another site's headers due to browser same-origin policy, so the Lambda is what makes "type a URL, get a verdict" work for any target.

```
  Browser ──> S3 as website (index.html, static)
     │
     └──GET ?url=TARGET──> Lambda Function URL ──> TARGET (server-side fetch, reads banner)
```

## Why each piece

- **S3**: hosts the static page. Cheap, no servers.
- **Lambda (Function URL)**: performs the cross-origin fetch the browser can't, reads   `Server` / `X-Powered-By` / `Set-Cookie`, returns JSON. SSRF-guarded. Written in   **Python 3 (standard library only)** — no pip install, no layer (see backend/lambda_function.py).

---

## 1. Deploy the Lambda (Python 3.12)

```bash
cd backend
zip function.zip lambda_function.py

aws lambda create-function \
  --function-name php2shell-scanner \
  --runtime python3.12 \
  --handler lambda_function.lambda_handler \
  --zip-file fileb://function.zip \
  --role arn:aws:iam::<ACCOUNT_ID>:role/<lambda-basic-exec-role> \
  --timeout 15 --memory-size 128 \
  --environment "Variables={ALLOWED_ORIGIN=https://scanner.example.com,FETCH_TIMEOUT_MS=8000}"

# Public HTTPS endpoint for the function:
aws lambda create-function-url-config \
  --function-name php2shell-scanner --auth-type NONE
aws lambda add-permission \
  --function-name php2shell-scanner --statement-id fnurl \
  --action lambda:InvokeFunctionUrl --principal "*" --function-url-auth-type NONE
```

Note the returned `FunctionUrl` (e.g. `https://xxxx.lambda-url.us-east-1.on.aws/`).
Set `ALLOWED_ORIGIN` to your real site origin so only your page can call it.

> The code uses only Python's standard library (`urllib`, `socket`, `ipaddress`), so the
> deploy is just the single `.py` file. Update later with:
> `aws lambda update-function-code --function-name php2shell-scanner --zip-file fileb://function.zip`

## 2. Host the frontend on S3

```bash
aws s3 mb s3://scanner-example-com
aws s3 cp index.html s3://scanner-example-com/index.html \
  --content-type "text/html; charset=utf-8" --cache-control "no-cache"
```

Keep the bucket **private** and serve through CloudFront with Origin Access Control
(don't use the legacy public-bucket "website hosting" mode).

## 3. Configure website for S3 bucket

```bash
aws s3 website s3://scanner-example-com/ \
    --index-document index.html \
    --error-document error.html
```

That's it. By default, the S3 bucket Website URL is `htttps://<bucket-name>.s3-website-<region>.amazonaws.com`

---

## Files

- `index.html` — the static frontend (upload to S3).
- `backend/lambda_function.py` — the Lambda scanner, Python 3 stdlib only (zip and deploy).
- `README.md` — this guide.
