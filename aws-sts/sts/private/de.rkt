#lang racket/base

(require (for-syntax racket/base
                     syntax/parse)
         (only-in http gmt-8601-string->seconds)
         racket/match
         "types.rkt")

(provide parse-assume-role-response
         parse-get-caller-identity-response)

;; xe - match an xexpr element and children
(define-match-expander xe
  (syntax-parser
    [(_ name:id attr-pat child-pats ...)
     #'(list* 'name attr-pat (list-no-order child-pats ... _ (... ...)))]))

;; xev - match an xexpr element and a single child
(define-match-expander xev
  (syntax-parser
    [(_ name:id attr-pat child-pat)
     #'(list 'name attr-pat child-pat)]))

(define parse-assumed-role-user
  (match-lambda
    [(xe AssumedRoleUser _
         (xev AssumedRoleId _ role-id)
         (xev Arn _ arn))
     (values role-id arn)]))

(define parse-credentials
  (match-lambda
    [(xe Credentials _
         (xev AccessKeyId _ access-key-id)
         (xev SecretAccessKey _ secret-access-key)
         (xev SessionToken _ session-token)
         (xev Expiration _ expiration))
     (credential access-key-id
                 secret-access-key
                 session-token
                 (gmt-8601-string->seconds expiration))]))

(define parse-assume-role-response
  (match-lambda
    [(xe AssumeRoleResponse _
         (xe AssumeRoleResult _
             (and (cons 'AssumedRoleUser _)
                  (app parse-assumed-role-user role-id arn))
             (and (cons 'Credentials _)
                  (app parse-credentials credentials))))
     (sts-assume-role-result role-id arn credentials)]))

(define parse-get-caller-identity-response
  (match-lambda
    [(xe GetCallerIdentityResponse _
         (xe GetCallerIdentityResult _
             (xev Arn _ arn)
             (xev UserId _ user-id)
             (xev Account _ account)))
     (sts-get-caller-identity-result arn user-id account)]))

