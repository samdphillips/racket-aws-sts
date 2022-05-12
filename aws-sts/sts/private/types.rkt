#lang racket/base

(provide (struct-out sts-assume-role-result)
         (struct-out credential)
         (struct-out sts-get-caller-identity-result))

(struct sts-assume-role-result (role-id arn credential) #:transparent)
(struct credential (access-key-id secret-access-key session-token expiration))

(struct sts-get-caller-identity-result (arn user-id account) #:transparent)

