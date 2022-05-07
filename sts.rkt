#lang racket/base

(require aws/keys
         aws/post
         aws/sigv4
         aws/util
         http/request
         racket/contract
         racket/match
         racket/stream
         xml/xexpr)

(provide (contract-out
           [sts (->* (string? (listof (list/c symbol? string?)))
                     ((-> xexpr? stream?))
                     stream?)]
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
    - Changed result from `list?` to `stream?`
      - Although I don't think that these results will ever be paged.

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
    (stream-append (result-proc x)
                   ;; If a NextToken element in the response XML, we need to
                   ;; call again to get more values.
                   (match (se-path* '(NextToken) x)
                     [#f '()]
                     [token (sts uri
                                 (set-next-token params token)
                                 result-proc)]))))



