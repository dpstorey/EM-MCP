#!/bin/bash
git clone https://gitlab.com/jwalley/tenable-ot-mcp.git
cd tenable-ot-mcp
docker build -t tenable-ot-mcp:local .

