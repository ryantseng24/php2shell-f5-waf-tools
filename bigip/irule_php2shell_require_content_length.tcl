when HTTP_REQUEST {
    # php2shell (CVE-2026-109618): a multipart body with no usable declared
    # length can get past PHP's post_max_size check, so refuse POST requests
    # that carry no Content-Length header.
    # Side effect: chunked uploads (Transfer-Encoding: chunked) are refused too.
    if { [HTTP::method] eq "POST" && ![HTTP::header exists "Content-Length"] } {
        HTTP::respond 411 content "Length Required" noserver Connection close
        return
    }
}
