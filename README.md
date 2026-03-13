# AI-Powered SOC Automation


The project demonstrates how AI agents can assist Security Operations Centers (SOC) by automatically analyzing security alerts, detecting patterns across related logs, and enriching investigations using threat intelligence sources.

---

## Project Overview

Security Operations Centers receive a large number of alerts daily, which can overwhelm analysts.  
This project introduces an **AI-driven analysis system** that helps automate the initial investigation of security alerts.

The system analyzes alerts from **Wazuh**, examines related logs to identify suspicious patterns, and uses external threat intelligence to support the investigation.

---

## System Architecture

The project simulates a small SOC environment consisting of:

- **Ubuntu** – the monitored machine generating logs  
- **Kali Linux** – used to simulate attacks  
- **Wazuh Server** – collects logs and generates security alerts  

Alerts are then analyzed by an **AI SOC Analyst Agent** that performs automated investigation.

---

## AI Investigation Process

The AI agent performs several analysis steps similar to a SOC analyst:

1. Retrieve alerts from **Wazuh**
2. Collect **neighboring alerts within a time window**
3. Analyze the context to identify suspicious **patterns**
4. Check public IP reputation using:
   - AbuseIPDB
   - GreyNoise
5. Generate a structured **security analysis**

---

## Features

- Automated SOC alert triage  
- Context-based alert analysis  
- Pattern detection across multiple alerts  
- Integration with threat intelligence sources  
- AI-generated investigation summary  
- Interactive dashboard built with Streamlit  

---

## Technologies Used

- Python  
- Streamlit  
- Wazuh SIEM  
- AI Agents  
- AbuseIPDB API  
- GreyNoise API  

---

## Authors

**Lyane R.**  
**Razan Al-Baqami**

Developed during the **Agentic AI Bootcamp – Tuwaiq Academy**
