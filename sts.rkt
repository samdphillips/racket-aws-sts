#lang racket/base

(require aws/keys
         aws/post
         aws/sigv4
         aws/util
         http/request
         racket/contract
         xml/xexpr
         "sts/private/de.rkt"
         "sts/private/types.rkt")

(provide (contract-out
           [sts (->* (string? (listof (list/c symbol? string?)))
                     ((-> xexpr? any))
                     any)]
           [sts-assume-role
             (->* (string? string?)
                  ((or/c #f positive?))
                  sts-assume-role-result?)]
           [sts-endpoint (parameter/c endpoint?)]
           [sts-region (parameter/c string?)]))

(define sts-region
  (make-parameter "us-east-1"))

;; XXX how to handle using the Global endpoint?
;; XXX this parameter could be derived from `sts-region`
(define sts-endpoint
  (make-parameter (endpoint "sts.us-east-1.amazonaws.com" #t)))

#|
  The STS service uses the AWS "Query" protocol, the same protocol that the SQS
  service uses.  This routine has been lifted from the AWS package SQS
  implementation.  Changes:

    - Moved contract boundary to module.
    - Changed result from `list?` to `any`, and removed paging

    https://github.com/greghendershott/aws/blob/94a16a6875ac585a10fc488b1bf48052172d5668/aws/sqs.rkt#L31
|#

(define (sts uri params [result-proc values])
  (ensure-have-keys)
  (let* ([date (seconds->gmt-8601-string 'basic (current-seconds))]
         [params (append params
                         `((AWSAccessKeyId ,(public-key))
                           (SignatureMethod "HmacSHA256")
                           (SignatureVersion "4")
                           (Timestamp ,date)
                           (Version "2011-10-01")))]
         [body (string->bytes/utf-8 (dict->form-urlencoded params))]
         [heads (hasheq 'Host (endpoint-host (sts-endpoint))
                        'Date date
                        'Content-Type "application/x-www-form-urlencoded; charset=utf-8")]
         [heads (add-v4-auth-heads #:heads   heads
                                   #:method  "POST"
                                   #:uri     uri
                                   #:sha256  (sha256-hex-string body)
                                   #:region  (sts-region)
                                   #:service "sts")]
         [x (post-with-retry uri params heads)])
    (result-proc x)))

; [O] DurationSeconds
; [O] ExternalId
; [O] Policy
; [O] PolicyArns.member.N
; [R] RoleArn
; [R] RoleSessionName
; [O] SerialNumber
; [O] SourceIdentity
; [O] Tags.member.N
; [O] TokenCode
; [O] TransitiveTagKeys.member.N
(define (sts-assume-role role-arn role-session-name [duration #f])
  (sts (endpoint->uri (sts-endpoint) "/")
       `((Action  "AssumeRole")
         (Version "2011-06-15")
         (RoleArn ,role-arn)
         (RoleSessionName ,role-session-name)
         .
         ,(if duration
              (list (list 'DurationSeconds (number->string duration)))
              null))
       parse-assume-role-response))
