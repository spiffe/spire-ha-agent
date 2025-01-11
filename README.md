# SPIRE HA Agent

[![Apache 2.0 License](https://img.shields.io/github/license/spiffe/helm-charts)](https://opensource.org/licenses/Apache-2.0)
[![Development Phase](https://github.com/spiffe/spiffe/blob/main/.img/maturity/dev.svg)](https://github.com/spiffe/spiffe/blob/main/MATURITY.md#development)

An agent to setup a SPIRE HA TrustDomain using two independent SPIRE Servers

## Warning

This code is very early in development and is very experimental. Please do not use it in production yet. Please do consider testing it out, provide feedback,
and maybe provide fixes.

## Simple Diagram

![diagram](diagram.png)

## Cross Linked Trust Diagram

![diagram](diagram2.png)

## How it Works

If the trust bundles of both servers are presented to the workload, it will not care which server instance a certificate is issued from. This agent provides
both trust bundles to the end user as one trust bundle, and will contact whichever server is responding to respond to x509 certificate or jwt token requests.
