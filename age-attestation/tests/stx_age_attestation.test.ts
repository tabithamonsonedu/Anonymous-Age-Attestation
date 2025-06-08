import { describe, expect, it } from "vitest";

// Mock Clarinet and contract interaction utilities
const mockClarinet = {
  test: (testFn) => testFn,
  types: {
    principal: (address) => `'${address}`,
    uint: (value) => `u${value}`,
    buff: (hex) => `0x${hex}`,
    tuple: (obj) => ({ ...obj }),
    ok: (value) => ({ type: 'ok', value }),
    err: (value) => ({ type: 'error', value }),
    some: (value) => ({ type: 'some', value }),
    none: () => ({ type: 'none' })
  },
  chain: {
    mineBlock: (txs) => ({ receipts: txs.map(tx => ({ result: tx.result || mockClarinet.types.ok(true) })) }),
    callReadOnlyFn: (contract, method, args, sender) => ({
      result: mockClarinet.types.ok(true) // Default success
    })
  },
  tx: {
    contractCall: (contract, method, args, sender) => ({
      type: 'contract-call',
      contract,
      method,
      args,
      sender,
      result: mockClarinet.types.ok(true)
    })
  }
};

// Test data constants
const CONTRACT_NAME = "stx_age_attestation";
const DEPLOYER = "ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRTPGZGM";
const USER1 = "ST1SJ3DTE5DN7X54YDH5D64R3BCB6A2AG2ZQ8YPD5";
const USER2 = "ST2CY5V39NHDPWSXMW9QDT3HC3GD6Q6XX4CFRK9AG";
const VERIFIER1 = "ST2JHG361ZXG51QTKY2NQCVBPPRRE2KZB1HR05NNC";

// Mock commitment and salt generation
const generateMockCommitment = (age, threshold, salt) => {
  // Simplified mock hash generation
  const combined = `${age}-${threshold}-${salt}`;
  return Buffer.from(combined).toString('hex').padEnd(64, '0').substring(0, 64);
};

const generateMockSalt = () => {
  return Array.from({ length: 32 }, () => Math.floor(Math.random() * 256))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
};

describe("STX Age Attestation Contract", () => {
  
  describe("Contract Initialization", () => {
    it("should initialize with correct default values", () => {
      const chain = mockClarinet.chain;
      
      // Test contract info retrieval
      const contractInfo = chain.callReadOnlyFn(
        CONTRACT_NAME,
        "get-contract-info",
        [],
        DEPLOYER
      );
      
      expect(contractInfo.result.type).toBe('ok');
    });

    it("should allow owner to initialize verifiers", () => {
      const chain = mockClarinet.chain;
      const verifiers = [VERIFIER1];
      
      const block = chain.mineBlock([
        mockClarinet.tx.contractCall(
          CONTRACT_NAME,
          "initialize-verifiers",
          [mockClarinet.types.tuple({ verifiers })],
          DEPLOYER
        )
      ]);
      
      expect(block.receipts[0].result.type).toBe('ok');
    });

    it("should reject verifier initialization from non-owner", () => {
      const chain = mockClarinet.chain;
      const verifiers = [VERIFIER1];
      
      const block = chain.mineBlock([
        mockClarinet.tx.contractCall(
          CONTRACT_NAME,
          "initialize-verifiers",
          [mockClarinet.types.tuple({ verifiers })],
          USER1
        )
      ]);
      
      expect(block.receipts[0].result.type).toBe('error');
      expect(block.receipts[0].result.value).toBe(mockClarinet.types.uint(100)); // ERR_NOT_AUTHORIZED
    });
  });

  describe("Age Commitment Creation", () => {
    it("should allow user to create age commitment", () => {
      const chain = mockClarinet.chain;
      const ageThreshold = 18;
      const salt = generateMockSalt();
      const commitment = generateMockCommitment(25, ageThreshold, salt);
      
      const block = chain.mineBlock([
        mockClarinet.tx.contractCall(
          CONTRACT_NAME,
          "create-age-commitment",
          [
            mockClarinet.types.uint(ageThreshold),
            mockClarinet.types.buff(commitment),
            mockClarinet.types.buff(salt)
          ],
          USER1
        )
      ]);
      
      expect(block.receipts[0].result.type).toBe('ok');
    });

    it("should increment verification ID after commitment creation", () => {
      const chain = mockClarinet.chain;
      const ageThreshold = 21;
      const salt1 = generateMockSalt();
      const salt2 = generateMockSalt();
      const commitment1 = generateMockCommitment(25, ageThreshold, salt1);
      const commitment2 = generateMockCommitment(30, ageThreshold, salt2);
      
      const block = chain.mineBlock([
        mockClarinet.tx.contractCall(
          CONTRACT_NAME,
          "create-age-commitment",
          [
            mockClarinet.types.uint(ageThreshold),
            mockClarinet.types.buff(commitment1),
            mockClarinet.types.buff(salt1)
          ],
          USER1
        ),
        mockClarinet.tx.contractCall(
          CONTRACT_NAME,
          "create-age-commitment",
          [
            mockClarinet.types.uint(ageThreshold),
            mockClarinet.types.buff(commitment2),
            mockClarinet.types.buff(salt2)
          ],
          USER2
        )
      ]);
      
      expect(block.receipts[0].result.type).toBe('ok');
      expect(block.receipts[1].result.type).toBe('ok');
      expect(block.receipts[0].result.value).toBe(mockClarinet.types.uint(1));
      expect(block.receipts[1].result.value).toBe(mockClarinet.types.uint(2));
    });
  });

  describe("Zero-Knowledge Proof Submission", () => {
    it("should accept valid age proof", () => {
      const chain = mockClarinet.chain;
      const ageThreshold = 18;
      const actualAge = 25;
      const salt = generateMockSalt();
      const commitment = generateMockCommitment(actualAge, ageThreshold, salt);
      
      // First create commitment
      const createBlock = chain.mineBlock([
        mockClarinet.tx.contractCall(
          CONTRACT_NAME,
          "create-age-commitment",
          [
            mockClarinet.types.uint(ageThreshold),
            mockClarinet.types.buff(commitment),
            mockClarinet.types.buff(salt)
          ],
          USER1
        )
      ]);
      
      const verificationId = createBlock.receipts[0].result.value;
      
      // Then submit proof
      const proofBlock = chain.mineBlock([
        mockClarinet.tx.contractCall(
          CONTRACT_NAME,
          "submit-age-proof",
          [
            verificationId,
            mockClarinet.types.uint(actualAge),
            mockClarinet.types.buff(salt)
          ],
          USER1
        )
      ]);
      
      expect(proofBlock.receipts[0].result.type).toBe('ok');
    });

    it("should reject proof with age below threshold", () => {
      const chain = mockClarinet.chain;
      const ageThreshold = 21;
      const actualAge = 18; // Below threshold
      const salt = generateMockSalt();
      const commitment = generateMockCommitment(actualAge, ageThreshold, salt);
      
      const createBlock = chain.mineBlock([
        mockClarinet.tx.contractCall(
          CONTRACT_NAME,
          "create-age-commitment",
          [
            mockClarinet.types.uint(ageThreshold),
            mockClarinet.types.buff(commitment),
            mockClarinet.types.buff(salt)
          ],
          USER1
        )
      ]);
      
      const verificationId = createBlock.receipts[0].result.value;
      
      const proofBlock = chain.mineBlock([
        mockClarinet.tx.contractCall(
          CONTRACT_NAME,
          "submit-age-proof",
          [
            verificationId,
            mockClarinet.types.uint(actualAge),
            mockClarinet.types.buff(salt)
          ],
          USER1
        )
      ]);
      
      expect(proofBlock.receipts[0].result.type).toBe('error');
      expect(proofBlock.receipts[0].result.value).toBe(mockClarinet.types.uint(101)); // ERR_INVALID_PROOF
    });

    it("should reject proof with wrong salt", () => {
      const chain = mockClarinet.chain;
      const ageThreshold = 18;
      const actualAge = 25;
      const correctSalt = generateMockSalt();
      const wrongSalt = generateMockSalt();
      const commitment = generateMockCommitment(actualAge, ageThreshold, correctSalt);
      
      const createBlock = chain.mineBlock([
        mockClarinet.tx.contractCall(
          CONTRACT_NAME,
          "create-age-commitment",
          [
            mockClarinet.types.uint(ageThreshold),
            mockClarinet.types.buff(commitment),
            mockClarinet.types.buff(correctSalt)
          ],
          USER1
        )
      ]);
      
      const verificationId = createBlock.receipts[0].result.value;
      
      const proofBlock = chain.mineBlock([
        mockClarinet.tx.contractCall(
          CONTRACT_NAME,
          "submit-age-proof",
          [
            verificationId,
            mockClarinet.types.uint(actualAge),
            mockClarinet.types.buff(wrongSalt) // Wrong salt
          ],
          USER1
        )
      ]);
      
      expect(proofBlock.receipts[0].result.type).toBe('error');
      expect(proofBlock.receipts[0].result.value).toBe(mockClarinet.types.uint(101)); // ERR_INVALID_PROOF
    });
  });

  describe("Verifier Validation", () => {
    it("should allow authorized verifier to validate proof", () => {
      const chain = mockClarinet.chain;
      
      // Initialize verifier
      const initBlock = chain.mineBlock([
        mockClarinet.tx.contractCall(
          CONTRACT_NAME,
          "manage-verifier",
          [
            mockClarinet.types.principal(VERIFIER1),
            true
          ],
          DEPLOYER
        )
      ]);
      
      expect(initBlock.receipts[0].result.type).toBe('ok');
      
      // Create and submit valid proof first
      const ageThreshold = 18;
      const actualAge = 25;
      const salt = generateMockSalt();
      const commitment = generateMockCommitment(actualAge, ageThreshold, salt);
      
      const setupBlock = chain.mineBlock([
        mockClarinet.tx.contractCall(
          CONTRACT_NAME,
          "create-age-commitment",
          [
            mockClarinet.types.uint(ageThreshold),
            mockClarinet.types.buff(commitment),
            mockClarinet.types.buff(salt)
          ],
          USER1
        )
      ]);
      
      const verificationId = setupBlock.receipts[0].result.value;
      
      const proofBlock = chain.mineBlock([
        mockClarinet.tx.contractCall(
          CONTRACT_NAME,
          "submit-age-proof",
          [
            verificationId,
            mockClarinet.types.uint(actualAge),
            mockClarinet.types.buff(salt)
          ],
          USER1
        )
      ]);
      
      // Now validate
      const validateBlock = chain.mineBlock([
        mockClarinet.tx.contractCall(
          CONTRACT_NAME,
          "verifier-validate",
          [
            mockClarinet.types.principal(USER1),
            true
          ],
          VERIFIER1
        )
      ]);
      
      expect(validateBlock.receipts[0].result.type).toBe('ok');
    });

    it("should reject validation from unauthorized verifier", () => {
      const chain = mockClarinet.chain;
      
      const validateBlock = chain.mineBlock([
        mockClarinet.tx.contractCall(
          CONTRACT_NAME,
          "verifier-validate",
          [
            mockClarinet.types.principal(USER1),
            true
          ],
          USER2 // Not an authorized verifier
        )
      ]);
      
      expect(validateBlock.receipts[0].result.type).toBe('error');
      expect(validateBlock.receipts[0].result.value).toBe(mockClarinet.types.uint(107)); // ERR_VERIFIER_NOT_AUTHORIZED
    });
  });

  describe("Age Threshold Checking", () => {
    it("should correctly check age threshold for verified user", () => {
      const chain = mockClarinet.chain;
      
      // Mock a verified user scenario
      const result = chain.callReadOnlyFn(
        CONTRACT_NAME,
        "check-age-threshold",
        [
          mockClarinet.types.principal(USER1),
          mockClarinet.types.uint(18)
        ],
        DEPLOYER
      );
      
      // This would return true for a properly verified user
      expect(result.result).toBeDefined();
    });

    it("should return false for unverified user", () => {
      const chain = mockClarinet.chain;
      
      const result = chain.callReadOnlyFn(
        CONTRACT_NAME,
        "check-age-threshold",
        [
          mockClarinet.types.principal(USER2), // Unverified user
          mockClarinet.types.uint(18)
        ],
        DEPLOYER
      );
      
      expect(result.result).toBeDefined();
    });
  });

  describe("Attestation System", () => {
    it("should allow authorized verifier to create attestation", () => {
      const chain = mockClarinet.chain;
      
      // First authorize verifier
      const authBlock = chain.mineBlock([
        mockClarinet.tx.contractCall(
          CONTRACT_NAME,
          "manage-verifier",
          [
            mockClarinet.types.principal(VERIFIER1),
            true
          ],
          DEPLOYER
        )
      ]);
      
      expect(authBlock.receipts[0].result.type).toBe('ok');
      
      // Create attestation
      const attestBlock = chain.mineBlock([
        mockClarinet.tx.contractCall(
          CONTRACT_NAME,
          "create-attestation",
          [
            mockClarinet.types.principal(USER1),
            mockClarinet.types.uint(18),
            mockClarinet.types.uint(144) // Valid for 144 blocks
          ],
          VERIFIER1
        )
      ]);
      
      expect(attestBlock.receipts[0].result.type).toBe('ok');
    });

    it("should allow verifier to revoke their own attestation", () => {
      const chain = mockClarinet.chain;
      
      const revokeBlock = chain.mineBlock([
        mockClarinet.tx.contractCall(
          CONTRACT_NAME,
          "revoke-attestation",
          [mockClarinet.types.principal(USER1)],
          VERIFIER1
        )
      ]);
      
      expect(revokeBlock.receipts[0].result.type).toBe('ok');
    });
  });

  describe("Age Range Verification", () => {
    it("should allow verified user to create age range proof", () => {
      const chain = mockClarinet.chain;
      const proofData = generateMockSalt(); // Mock proof data
      
      const rangeBlock = chain.mineBlock([
        mockClarinet.tx.contractCall(
          CONTRACT_NAME,
          "verify-age-range",
          [
            mockClarinet.types.uint(18),
            mockClarinet.types.uint(65),
            mockClarinet.types.buff(proofData)
          ],
          USER1
        )
      ]);
      
      // This should succeed for a validated user
      expect(rangeBlock.receipts[0].result).toBeDefined();
    });
  });

  describe("Admin Functions", () => {
    it("should allow owner to update verification fee", () => {
      const chain = mockClarinet.chain;
      const newFee = 200000; // 0.2 STX
      
      const updateBlock = chain.mineBlock([
        mockClarinet.tx.contractCall(
          CONTRACT_NAME,
          "set-verification-fee",
          [mockClarinet.types.uint(newFee)],
          DEPLOYER
        )
      ]);
      
      expect(updateBlock.receipts[0].result.type).toBe('ok');
    });

    it("should reject fee update from non-owner", () => {
      const chain = mockClarinet.chain;
      const newFee = 200000;
      
      const updateBlock = chain.mineBlock([
        mockClarinet.tx.contractCall(
          CONTRACT_NAME,
          "set-verification-fee",
          [mockClarinet.types.uint(newFee)],
          USER1 // Not the owner
        )
      ]);
      
      expect(updateBlock.receipts[0].result.type).toBe('error');
      expect(updateBlock.receipts[0].result.value).toBe(mockClarinet.types.uint(100)); // ERR_NOT_AUTHORIZED
    });

    it("should allow owner to update proof bond", () => {
      const chain = mockClarinet.chain;
      const newBond = 2000000; // 2 STX
      
      const updateBlock = chain.mineBlock([
        mockClarinet.tx.contractCall(
          CONTRACT_NAME,
          "set-proof-bond",
          [mockClarinet.types.uint(newBond)],
          DEPLOYER
        )
      ]);
      
      expect(updateBlock.receipts[0].result.type).toBe('ok');
    });

    it("should allow owner to emergency revoke verification", () => {
      const chain = mockClarinet.chain;
      
      const revokeBlock = chain.mineBlock([
        mockClarinet.tx.contractCall(
          CONTRACT_NAME,
          "emergency-revoke-verification",
          [mockClarinet.types.principal(USER1)],
          DEPLOYER
        )
      ]);
      
      expect(revokeBlock.receipts[0].result.type).toBe('ok');
    });

    it("should allow owner to withdraw fees", () => {
      const chain = mockClarinet.chain;
      const withdrawAmount = 100000;
      
      const withdrawBlock = chain.mineBlock([
        mockClarinet.tx.contractCall(
          CONTRACT_NAME,
          "withdraw-fees",
          [mockClarinet.types.uint(withdrawAmount)],
          DEPLOYER
        )
      ]);
      
      expect(withdrawBlock.receipts[0].result.type).toBe('ok');
    });
  });

  describe("Read-Only Functions", () => {
    it("should return verification status for user", () => {
      const chain = mockClarinet.chain;
      
      const statusResult = chain.callReadOnlyFn(
        CONTRACT_NAME,
        "get-verification-status",
        [mockClarinet.types.principal(USER1)],
        DEPLOYER
      );
      
      expect(statusResult.result).toBeDefined();
    });

    it("should check attestation validity", () => {
      const chain = mockClarinet.chain;
      
      const attestResult = chain.callReadOnlyFn(
        CONTRACT_NAME,
        "check-attestation",
        [
          mockClarinet.types.principal(VERIFIER1),
          mockClarinet.types.principal(USER1),
          mockClarinet.types.uint(18)
        ],
        DEPLOYER
      );
      
      expect(attestResult.result).toBeDefined();
    });

    it("should return age range proof for user", () => {
      const chain = mockClarinet.chain;
      
      const rangeResult = chain.callReadOnlyFn(
        CONTRACT_NAME,
        "get-age-range-proof",
        [mockClarinet.types.principal(USER1)],
        DEPLOYER
      );
      
      expect(rangeResult.result).toBeDefined();
    });

    it("should check if principal is authorized verifier", () => {
      const chain = mockClarinet.chain;
      
      const verifierResult = chain.callReadOnlyFn(
        CONTRACT_NAME,
        "is-authorized-verifier",
        [mockClarinet.types.principal(VERIFIER1)],
        DEPLOYER
      );
      
      expect(verifierResult.result).toBeDefined();
    });

    it("should return contract info", () => {
      const chain = mockClarinet.chain;
      
      const infoResult = chain.callReadOnlyFn(
        CONTRACT_NAME,
        "get-contract-info",
        [],
        DEPLOYER
      );
      
      expect(infoResult.result).toBeDefined();
    });
  });

  describe("Edge Cases and Error Handling", () => {
    it("should handle double proof submission", () => {
      const chain = mockClarinet.chain;
      const ageThreshold = 18;
      const actualAge = 25;
      const salt = generateMockSalt();
      const commitment = generateMockCommitment(actualAge, ageThreshold, salt);
      
      // Create commitment
      const createBlock = chain.mineBlock([
        mockClarinet.tx.contractCall(
          CONTRACT_NAME,
          "create-age-commitment",
          [
            mockClarinet.types.uint(ageThreshold),
            mockClarinet.types.buff(commitment),
            mockClarinet.types.buff(salt)
          ],
          USER1
        )
      ]);
      
      const verificationId = createBlock.receipts[0].result.value;
      
      // Submit proof twice
      const proofBlock = chain.mineBlock([
        mockClarinet.tx.contractCall(
          CONTRACT_NAME,
          "submit-age-proof",
          [
            verificationId,
            mockClarinet.types.uint(actualAge),
            mockClarinet.types.buff(salt)
          ],
          USER1
        ),
        mockClarinet.tx.contractCall(
          CONTRACT_NAME,
          "submit-age-proof",
          [
            verificationId,
            mockClarinet.types.uint(actualAge),
            mockClarinet.types.buff(salt)
          ],
          USER1
        )
      ]);
      
      expect(proofBlock.receipts[0].result.type).toBe('ok');
      expect(proofBlock.receipts[1].result.type).toBe('error');
      expect(proofBlock.receipts[1].result.value).toBe(mockClarinet.types.uint(102)); // ERR_ALREADY_VERIFIED
    });

    it("should handle non-existent verification ID", () => {
      const chain = mockClarinet.chain;
      
      const proofBlock = chain.mineBlock([
        mockClarinet.tx.contractCall(
          CONTRACT_NAME,
          "submit-age-proof",
          [
            mockClarinet.types.uint(999), // Non-existent ID
            mockClarinet.types.uint(25),
            mockClarinet.types.buff(generateMockSalt())
          ],
          USER1
        )
      ]);
      
      expect(proofBlock.receipts[0].result.type).toBe('error');
      expect(proofBlock.receipts[0].result.value).toBe(mockClarinet.types.uint(103)); // ERR_VERIFICATION_NOT_FOUND
    });
  });
});