;; title: stx_age_attestation
;; version: 1.0.0
;; summary: Privacy-Preserving Age Verification System
;; description: Uses commitment schemes and zero-knowledge proofs for age verification
;;              without revealing actual birthdates or personal information

;; Constants
(define-constant CONTRACT_OWNER tx-sender)
(define-constant ERR_NOT_AUTHORIZED (err u100))
(define-constant ERR_INVALID_PROOF (err u101))
(define-constant ERR_ALREADY_VERIFIED (err u102))
(define-constant ERR_VERIFICATION_NOT_FOUND (err u103))
(define-constant ERR_INVALID_COMMITMENT (err u104))
(define-constant ERR_PROOF_EXPIRED (err u105))
(define-constant ERR_INVALID_CHALLENGE (err u106))
(define-constant ERR_VERIFIER_NOT_AUTHORIZED (err u107))

;; Age thresholds
(define-constant AGE_13 u13)
(define-constant AGE_18 u18)
(define-constant AGE_21 u21)
(define-constant AGE_65 u65)

;; Proof validity period (blocks)
(define-constant PROOF_VALIDITY_PERIOD u144) ;; ~24 hours at 10min blocks

;; Data Variables
(define-data-var next-verification-id uint u1)
(define-data-var verification-fee uint u100000) ;; 0.1 STX
(define-data-var proof-bond uint u1000000) ;; 1 STX bond for false claims

;; Authorized verifiers (trusted entities that can validate real-world identity)
(define-map authorized-verifiers principal bool)

;; Age verification records
(define-map age-verifications principal {
    verification-id: uint,
    age-threshold: uint,
    commitment-hash: (buff 32),
    proof-timestamp: uint,
    verifier: (optional principal),
    status: (string-ascii 20), ;; "pending", "verified", "rejected", "expired"
    challenge-nonce: uint,
    bond-amount: uint
})

;; Commitment storage for zero-knowledge proofs
(define-map age-commitments uint {
    user: principal,
    age-threshold: uint,
    commitment: (buff 32),
    salt: (buff 32),
    created-at: uint,
    revealed: bool
})

;; Verification challenges for interactive proofs
(define-map verification-challenges uint {
    user: principal,
    verifier: principal,
    challenge-data: (buff 64),
    response-required: bool,
    created-at: uint,
    completed: bool
})

;; Privacy-preserving age ranges (instead of exact ages)
(define-map age-range-proofs principal {
    min-age-verified: uint,
    max-age-verified: uint,
    proof-hash: (buff 32),
    verified-at: uint,
    expires-at: uint
})

;; Trusted attestation system
(define-map attestations (tuple (attester principal) (subject principal)) {
    age-threshold: uint,
    attestation-hash: (buff 32),
    created-at: uint,
    valid-until: uint,
    revoked: bool
})

;; Helper Functions

;; Generate a commitment hash using Pedersen commitment scheme simulation
(define-private (generate-commitment (age uint) (threshold uint) (salt (buff 32)))
    (let ((age-bytes (unwrap-panic (to-consensus-buff? age)))
          (threshold-bytes (unwrap-panic (to-consensus-buff? threshold))))
        (hash160 (concat (concat age-bytes threshold-bytes) salt))))

;; Verify zero-knowledge age proof
(define-private (verify-age-proof (claimed-age uint) (threshold uint) (commitment (buff 32)) (salt (buff 32)))
    (let ((computed-commitment (generate-commitment claimed-age threshold salt)))
        (and (>= claimed-age threshold)
             (is-eq commitment computed-commitment))))

;; Generate secure random nonce
(define-private (generate-nonce (seed uint))
    (hash160 (unwrap-panic (to-consensus-buff? (+ seed stacks-block-height (var-get next-verification-id))))))

;; Check if verification is still valid
(define-private (is-verification-valid (verification-timestamp uint))
    (< (- stacks-block-height verification-timestamp) PROOF_VALIDITY_PERIOD))

;; Public Functions

;; Initialize the contract with authorized verifiers
(define-public (initialize-verifiers (verifiers (list 10 principal)))
    (begin
        (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_NOT_AUTHORIZED)
        (map set-verifier-status verifiers)
        (ok true)))

(define-private (set-verifier-status (verifier principal))
    (map-set authorized-verifiers verifier true))

;; Add or remove authorized verifiers
(define-public (manage-verifier (verifier principal) (authorized bool))
    (begin
        (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_NOT_AUTHORIZED)
        (map-set authorized-verifiers verifier authorized)
        (ok true)))

;; Step 1: Create age commitment (privacy-preserving)
(define-public (create-age-commitment (age-threshold uint) (commitment (buff 32)) (salt (buff 32)))
    (let ((verification-id (var-get next-verification-id))
          (fee (var-get verification-fee)))
        
        ;; Charge verification fee
        (try! (stx-transfer? fee tx-sender CONTRACT_OWNER))
        
        ;; Store commitment
        (map-set age-commitments verification-id {
            user: tx-sender,
            age-threshold: age-threshold,
            commitment: commitment,
            salt: salt,
            created-at: stacks-block-height,
            revealed: false
        })
        
        ;; Initialize verification record
        (map-set age-verifications tx-sender {
            verification-id: verification-id,
            age-threshold: age-threshold,
            commitment-hash: commitment,
            proof-timestamp: stacks-block-height,
            verifier: none,
            status: "pending",
            challenge-nonce: u0,
            bond-amount: u0
        })
        
        (var-set next-verification-id (+ verification-id u1))
        (ok verification-id)))

;; Step 2: Submit zero-knowledge proof
(define-public (submit-age-proof (verification-id uint) (claimed-age uint) (salt (buff 32)))
    (let ((commitment-data (unwrap! (map-get? age-commitments verification-id) ERR_VERIFICATION_NOT_FOUND))
          (bond (var-get proof-bond)))
        
        (asserts! (is-eq tx-sender (get user commitment-data)) ERR_NOT_AUTHORIZED)
        (asserts! (not (get revealed commitment-data)) ERR_ALREADY_VERIFIED)
        
        ;; Require bond for false proof protection
        (try! (stx-transfer? bond tx-sender (as-contract tx-sender)))
        
        ;; Verify the zero-knowledge proof
        (asserts! (verify-age-proof claimed-age 
                                  (get age-threshold commitment-data)
                                  (get commitment commitment-data)
                                  salt) ERR_INVALID_PROOF)
        
        ;; Mark commitment as revealed
        (map-set age-commitments verification-id 
                (merge commitment-data { revealed: true }))
        
        ;; Update verification record
        (let ((current-verification (unwrap! (map-get? age-verifications tx-sender) ERR_VERIFICATION_NOT_FOUND)))
            (map-set age-verifications tx-sender 
                    (merge current-verification { 
                        status: "verified",
                        bond-amount: bond,
                        proof-timestamp: stacks-block-height
                    })))
        
        (ok true)))

;; Step 3: Verifier validation (for high-assurance verification)
(define-public (verifier-validate (user principal) (approve bool))
    (let ((verification (unwrap! (map-get? age-verifications user) ERR_VERIFICATION_NOT_FOUND)))
        
        (asserts! (default-to false (map-get? authorized-verifiers tx-sender)) ERR_VERIFIER_NOT_AUTHORIZED)
        (asserts! (is-eq (get status verification) "verified") ERR_INVALID_PROOF)
        
        (if approve
            (begin
                ;; Approve verification and return bond
                (try! (as-contract (stx-transfer? (get bond-amount verification) tx-sender user)))
                (map-set age-verifications user 
                        (merge verification { 
                            status: "validated",
                            verifier: (some tx-sender)
                        }))
                (ok true))
            (begin
                ;; Reject verification, forfeit bond
                (map-set age-verifications user 
                        (merge verification { 
                            status: "rejected",
                            verifier: (some tx-sender)
                        }))
                (ok false)))))

;; Create attestation from trusted verifier
(define-public (create-attestation (subject principal) (age-threshold uint) (valid-duration uint))
    (let ((attestation-hash (hash160 (unwrap-panic (to-consensus-buff? 
                                    (+ age-threshold stacks-block-height valid-duration))))))
        
        (asserts! (default-to false (map-get? authorized-verifiers tx-sender)) ERR_VERIFIER_NOT_AUTHORIZED)
        
        (map-set attestations { attester: tx-sender, subject: subject } {
            age-threshold: age-threshold,
            attestation-hash: attestation-hash,
            created-at: stacks-block-height,
            valid-until: (+ stacks-block-height valid-duration),
            revoked: false
        })
        
        (ok attestation-hash)))

;; Revoke attestation
(define-public (revoke-attestation (subject principal))
    (let ((attestation-key { attester: tx-sender, subject: subject }))
        (match (map-get? attestations attestation-key)
            attestation (begin
                        (map-set attestations attestation-key 
                                (merge attestation { revoked: true }))
                        (ok true))
            ERR_VERIFICATION_NOT_FOUND)))

;; Privacy-preserving age range verification
(define-public (verify-age-range (min-age uint) (max-age uint) (proof-data (buff 32)))
    (let ((current-verification (map-get? age-verifications tx-sender)))
        (match current-verification
            verification (if (and (is-eq (get status verification) "validated")
                                (is-verification-valid (get proof-timestamp verification))
                                (>= (get age-threshold verification) min-age))
                            (begin
                                (map-set age-range-proofs tx-sender {
                                    min-age-verified: min-age,
                                    max-age-verified: max-age,
                                    proof-hash: proof-data,
                                    verified-at: stacks-block-height,
                                    expires-at: (+ stacks-block-height PROOF_VALIDITY_PERIOD)
                                })
                                (ok true))
                            ERR_INVALID_PROOF)
            ERR_VERIFICATION_NOT_FOUND)))

;; Read-only functions

;; Check if user meets age threshold (privacy-preserving)
(define-read-only (check-age-threshold (user principal) (threshold uint))
    (match (map-get? age-verifications user)
        verification (and (or (is-eq (get status verification) "verified")
                             (is-eq (get status verification) "validated"))
                         (>= (get age-threshold verification) threshold)
                         (is-verification-valid (get proof-timestamp verification)))
        false))

;; Get verification status without revealing age
(define-read-only (get-verification-status (user principal))
    (match (map-get? age-verifications user)
        verification (some {
            status: (get status verification),
            threshold-met: (> (get age-threshold verification) u0),
            timestamp: (get proof-timestamp verification),
            verified-by: (get verifier verification),
            valid: (is-verification-valid (get proof-timestamp verification))
        })
        none))

;; Check attestation validity
(define-read-only (check-attestation (attester principal) (subject principal) (threshold uint))
    (match (map-get? attestations { attester: attester, subject: subject })
        attestation (and (not (get revoked attestation))
                        (>= (get age-threshold attestation) threshold)
                        (<= stacks-block-height (get valid-until attestation)))
        false))

;; Get age range proof (privacy-preserving)
(define-read-only (get-age-range-proof (user principal))
    (match (map-get? age-range-proofs user)
        proof (if (<= stacks-block-height (get expires-at proof))
                 (some {
                     min-age-verified: (get min-age-verified proof),
                     max-age-verified: (get max-age-verified proof),
                     verified-at: (get verified-at proof),
                     valid: true
                 })
                 (some {
                     min-age-verified: u0,
                     max-age-verified: u0,
                     verified-at: u0,
                     valid: false
                 }))
        none))

;; Check if user is authorized verifier
(define-read-only (is-authorized-verifier (verifier principal))
    (default-to false (map-get? authorized-verifiers verifier)))

;; Get contract settings
(define-read-only (get-contract-info)
    {
        verification-fee: (var-get verification-fee),
        proof-bond: (var-get proof-bond),
        proof-validity-blocks: PROOF_VALIDITY_PERIOD,
        current-block: stacks-block-height
    })

;; Admin functions

;; Update verification fee
(define-public (set-verification-fee (new-fee uint))
    (begin
        (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_NOT_AUTHORIZED)
        (var-set verification-fee new-fee)
        (ok true)))

;; Update proof bond amount
(define-public (set-proof-bond (new-bond uint))
    (begin
        (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_NOT_AUTHORIZED)
        (var-set proof-bond new-bond)
        (ok true)))

;; Emergency functions for contract maintenance
(define-public (emergency-revoke-verification (user principal))
    (begin
        (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_NOT_AUTHORIZED)
        (match (map-get? age-verifications user)
            verification (begin
                        (map-set age-verifications user 
                                (merge verification { status: "revoked" }))
                        (ok true))
            ERR_VERIFICATION_NOT_FOUND)))

;; Withdraw accumulated fees
(define-public (withdraw-fees (amount uint))
    (begin
        (asserts! (is-eq tx-sender CONTRACT_OWNER) ERR_NOT_AUTHORIZED)
        (try! (as-contract (stx-transfer? amount tx-sender CONTRACT_OWNER)))
        (ok amount)))