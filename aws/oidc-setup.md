# GitHub Actions → AWS OIDC Setup Guide

This guide configures GitHub Actions to authenticate with AWS via OIDC (OpenID Connect),
eliminating the need for static IAM access keys as GitHub Secrets.

**Why OIDC instead of static keys?**
- No exportable credentials stored in GitHub Secrets
- Token is short-lived (15 minutes max)
- Scoped to specific repository + branch via IAM trust policy conditions
- If runner is compromised, blast radius is limited to rotation role permissions

---

## Step 1: Create the OIDC Identity Provider in AWS

```bash
aws iam create-open-id-connect-provider \
  --url https://token.actions.githubusercontent.com \
  --client-id-list sts.amazonaws.com \
  --thumbprint-list 6938fd4d98bab03faadb97b34396831e3780aea1
```

Verify:
```bash
aws iam list-open-id-connect-providers
```

---

## Step 2: Create the IAM Role Trust Policy

Save as `rotation-role-trust.json`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::YOUR_ACCOUNT_ID:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
        },
        "StringLike": {
          "token.actions.githubusercontent.com:sub": "repo:YOUR_ORG/devsecops-challenge:*"
        }
      }
    }
  ]
}
```

Replace `YOUR_ACCOUNT_ID` and `YOUR_ORG/devsecops-challenge` with your values.

For tighter security, restrict to `main` branch only:
```json
"token.actions.githubusercontent.com:sub": "repo:YOUR_ORG/devsecops-challenge:ref:refs/heads/main"
```

---

## Step 3: Create the IAM Role

```bash
aws iam create-role \
  --role-name pagos-github-actions-rotation \
  --assume-role-policy-document file://rotation-role-trust.json \
  --description "GitHub Actions rotation role — OIDC, no static keys"

# Attach the rotation-agent policy
aws iam attach-role-policy \
  --role-name pagos-github-actions-rotation \
  --policy-arn arn:aws:iam::YOUR_ACCOUNT_ID:policy/pagos-rotation-agent-policy
```

Note the role ARN:
```bash
aws iam get-role --role-name pagos-github-actions-rotation \
  --query 'Role.Arn' --output text
```

---

## Step 4: Configure GitHub Repository

1. Go to: `Settings → Variables → Actions variables`
2. Add variable: `ROTATION_ROLE_ARN` = `arn:aws:iam::YOUR_ACCOUNT_ID:role/pagos-github-actions-rotation`

Do NOT add this as a Secret — it's not sensitive.

---

## Step 5: Update the Workflow

In `.github/workflows/rotate-secrets.yml`, add to the `rotate` job:

```yaml
permissions:
  id-token: write   # Required for OIDC
  contents: read

steps:
  - name: Configure AWS credentials via OIDC
    uses: aws-actions/configure-aws-credentials@v4
    with:
      role-to-assume: ${{ vars.ROTATION_ROLE_ARN }}
      aws-region: us-east-1
      role-session-name: GitHubActionsRotation
```

---

## Verification

```bash
# In the workflow, after credential configuration:
aws sts get-caller-identity
# Should show: pagos-github-actions-rotation
```

---

## Demo Mode Note

The CI demo in this repository uses Vault with `VAULT_TOKEN` as a GitHub Secret
(dummy value for evaluators). The OIDC configuration above is the production AWS
pattern — it's documented here but not executed in the demo.

To run against real AWS in CI:
1. Complete steps 1–4 above
2. Update `rotate-secrets.yml` to include the OIDC step
3. Change `--backend vault` to `--backend aws` in the rotation step
