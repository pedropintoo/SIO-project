# **Final Report Structure**

## **1. Introduction**
- Brief overview of the project, its goals, and its main functionalities.
- Technologies used:
  - Why MongoDB was chosen as the database and its integration into the project.
  - Role of Docker in the setup and execution process.
- Instructions for running the server and client.

---

## **2. Secure Operations**

### **2.1 Local commands**

### **2.2 Commands that use the anonymous API**

### **2.3 Commands that use the authenticated API**

### **2.4 Commands that use the authorized API**

### **Sequence Diagrams**

- Diagrams illustrating secure workflows for:
  - Creating a subject.
  - Creating an organization.
  - Creating a session.

### **Secure Operations Overview**

- Brief explanations of the secure mechanisms employed in the project:
  1. **PBKDF2HMAC**: Derivation of master keys.
  2. **ECC**: Generation of private and public keys, and secure key exchanges.
  3. **ECDSA**: Signing data for authenticity and integrity.
  4. **ECDH**: Derivation of shared keys during session creation.
  5. **HKDF**: Creation of session-specific encryption keys.
  6. **AES-GCM**: Confidentiality and integrity for sensitive data.
  7. **SHA-256**: File handles and integrity verification.
  8. **Replay Attack Prevention**: Updating and validating `msg_id`.
  9. **Data Encapsulation**: Secure and integral transmission of session data.
  10. **Signed Server Responses**: Authenticity of server-provided data.
  11. **Soft Deletion**: Metadata-based control of document accessibility.
  12. **Encrypted Key Storage**: Secure management of document encryption keys.
  13. **Integrity Checks**: Verification of decrypted content against its hash.

---

## **3. Analysis of the Software**
### **3.1 Scope of Analysis**
- Specify the selected chapter of ASVS (V2, V3, V4, or V6) and explain its relevance to the project.

### **3.2 Control Applicability and Justification**
- For each control in the chosen ASVS chapter:
  - State whether it is applicable.
  - Justify the decision (e.g., why it is applicable or not).
  - Provide evidence (e.g., code snippets, logs, screenshots) for applicable controls.

---

## **4. Testing and Validation**
### **4.1 Testing Approach**
- Describe the `./run_tests` file and its role in validating the project.
- Explain the types of tests conducted:
  - Functional tests.
  - Security-related tests (if applicable).

### **4.2 Testing Outcomes**
- Present evidence of test results, such as:
  - Logs showing successful and failed test cases.
  - Screenshots of test outputs or coverage reports.

---

## **5. Conclusion**
- Summary of the project:
  - Achievements.
  - Implemented secure features.
- Lessons learned:
  - Challenges encountered and how they were addressed.
  - Areas for improvement or future work.
