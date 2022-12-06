/*
 * A partial implementation of HTTP/1.0
 *
 * This code is mainly intended as a replacement for the book's 'tiny.c' server
 * It provides a *partial* implementation of HTTP/1.0 which can form a basis for
 * the assignment.
 *
 * @author G. Back for CS 3214 Spring 2018
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <regex.h>
#include <jansson.h>
#include <jwt.h>
#include <dirent.h>

#include "http.h"
#include "hexdump.h"
#include "socket.h"
#include "bufio.h"
#include "main.h"

static const char * SECRET_IN_CODE = "i just did ha";

// Need macros here because of the sizeof
#define CRLF "\r\n"
#define CR "\r"
#define STARTS_WITH(field_name, header) \
    (!strncasecmp(field_name, header, sizeof(header) - 1))

bool is_auth = false;
/* Parse HTTP request line, setting req_method, req_path, and req_version. */
static bool
http_parse_request(struct http_transaction *ta)
{
    size_t req_offset;
    ssize_t len = bufio_readline(ta->client->bufio, &req_offset);
    if (len < 2)       // error, EOF, or less than 2 characters
        return false;

    char *request = bufio_offset2ptr(ta->client->bufio, req_offset);
    request[len-2] = '\0';  // replace LF with 0 to ensure zero-termination
    char *endptr;
    char *method = strtok_r(request, " ", &endptr);
    if (method == NULL)
        return false;

    if (!strcmp(method, "GET"))
        ta->req_method = HTTP_GET;
    else if (!strcmp(method, "POST"))
        ta->req_method = HTTP_POST;
    else
        ta->req_method = HTTP_UNKNOWN;

    char *req_path = strtok_r(NULL, " ", &endptr);
    if (req_path == NULL)
        return false;

    ta->req_path = bufio_ptr2offset(ta->client->bufio, req_path);

    char *http_version = strtok_r(NULL, CR, &endptr);
    if (http_version == NULL)  // would be HTTP 0.9
        return false;

    // record client's HTTP version in request
    if (!strcmp(http_version, "HTTP/1.1"))
        ta->req_version = HTTP_1_1;
    else if (!strcmp(http_version, "HTTP/1.0"))
        ta->req_version = HTTP_1_0;
    else
        return false;

    return true;
}

/* Process HTTP headers. */
static bool
http_process_headers(struct http_transaction *ta)
{
    for (;;) {
        size_t header_offset;
        ssize_t len = bufio_readline(ta->client->bufio, &header_offset);
        if (len <= 0)
            return false;

        char *header = bufio_offset2ptr(ta->client->bufio, header_offset);
        if (len == 2 && STARTS_WITH(header, CRLF))       // empty CRLF
            return true;

        header[len-2] = '\0';
        /* Each header field consists of a name followed by a 
         * colon (":") and the field value. Field names are 
         * case-insensitive. The field value MAY be preceded by 
         * any amount of LWS, though a single SP is preferred.
         */
        char *endptr;
        char *field_name = strtok_r(header, ":", &endptr);
        if (field_name == NULL)
            return false;

        // skip white space
        char *field_value = endptr;
        while (*field_value == ' ' || *field_value == '\t')
            field_value++;

        // you may print the header like so
        // printf("Header: %s: %s\n", field_name, field_value);
        if (!strcasecmp(field_name, "Content-Length")) {
            ta->req_content_len = atoi(field_value);
        }

        /* Handle other headers here. Both field_value and field_name
         * are zero-terminated strings.
         */
        if (!strcasecmp(field_name, "Cookie")) {
            ta->cookie = field_value;
        }

        if (!strcasecmp(field_name, "Range")) {
            ta->exist = true;
            if (sscanf(field_value, "bytes=%d-%d", &ta->vidstart,&ta->vidend) == 1) {
                ta->vidend = -1;
            }
        }

        
        

    }
}

const int MAX_HEADER_LEN = 2048;

/* add a formatted header to the response buffer. */
void 
http_add_header(buffer_t * resp, char* key, char* fmt, ...)
{
    va_list ap;

    buffer_appends(resp, key);
    buffer_appends(resp, ": ");

    va_start(ap, fmt);
    char *error = buffer_ensure_capacity(resp, MAX_HEADER_LEN);
    int len = vsnprintf(error, MAX_HEADER_LEN, fmt, ap);
    resp->len += len > MAX_HEADER_LEN ? MAX_HEADER_LEN - 1 : len;
    va_end(ap);

    buffer_appends(resp, "\r\n");
}

/* add a content-length header. */
static void
add_content_length(buffer_t *res, size_t len)
{
    // fprintf(stderr, "\n%ld\n", len);
    http_add_header(res, "Content-Length", "%ld", len);
}

/* start the response by writing the first line of the response 
 * to the response buffer.  Used in send_response_header */
static void
start_response(struct http_transaction * ta, buffer_t *res)
{
    if (ta->req_version == HTTP_1_0) {
        buffer_appends(res, "HTTP/1.0 ");
    }
    else {
        buffer_appends(res, "HTTP/1.1 ");
    }
    switch (ta->resp_status) {
    case HTTP_OK:
        buffer_appends(res, "200 OK");
        break;
    case HTTP_PARTIAL_CONTENT:
        buffer_appends(res, "206 Partial Content");
        break;
    case HTTP_BAD_REQUEST:
        buffer_appends(res, "400 Bad Request");
        break;
    case HTTP_PERMISSION_DENIED:
        buffer_appends(res, "403 Permission Denied");
        break;
    case HTTP_NOT_FOUND:
        buffer_appends(res, "404 Not Found");
        break;
    case HTTP_METHOD_NOT_ALLOWED:
        buffer_appends(res, "405 Method Not Allowed");
        break;
    case HTTP_REQUEST_TIMEOUT:
        buffer_appends(res, "408 Request Timeout");
        break;
    case HTTP_REQUEST_TOO_LONG:
        buffer_appends(res, "414 Request Too Long");
        break;
    case HTTP_NOT_IMPLEMENTED:
        buffer_appends(res, "501 Not Implemented");
        break;
    case HTTP_SERVICE_UNAVAILABLE:
        buffer_appends(res, "503 Service Unavailable");
        break;
    case HTTP_INTERNAL_ERROR:
    default:
        buffer_appends(res, "500 Internal Server Error");
        break;
    }
    buffer_appends(res, CRLF);
}

/* Send response headers to client */
static bool
send_response_header(struct http_transaction *ta)
{
    buffer_t response;
    buffer_init(&response, 80);

    start_response(ta, &response);
    if (bufio_sendbuffer(ta->client->bufio, &response) == -1) {
        return false;
    }

    buffer_appends(&ta->resp_headers, CRLF);
    if (bufio_sendbuffer(ta->client->bufio, &ta->resp_headers) == -1) {
        return false;
    }

    buffer_delete(&response);
    return true;
}

/* Send a full response to client with the content in resp_body. */
static bool
send_response(struct http_transaction *ta)
{
    // add content-length.  All other headers must have already been set.
    add_content_length(&ta->resp_headers, ta->resp_body.len);

    if (!send_response_header(ta))
        return false;
    // bool b = 
    // fprintf(stderr, "\n%d\n", b);
    return bufio_sendbuffer(ta->client->bufio, &ta->resp_body) != -1;
}

const int MAX_ERROR_LEN = 2048;

/* Send an error response. */
static bool
send_error(struct http_transaction * ta, enum http_response_status status, const char *fmt, ...)
{
    // fprintf(stderr, "in send error");
    va_list ap;

    va_start(ap, fmt);
    char *error = buffer_ensure_capacity(&ta->resp_body, MAX_ERROR_LEN);
    int len = vsnprintf(error, MAX_ERROR_LEN, fmt, ap);
    ta->resp_body.len += len > MAX_ERROR_LEN ? MAX_ERROR_LEN - 1 : len;
    va_end(ap);
    ta->resp_status = status;
    char *req_path = bufio_offset2ptr(ta->client->bufio, ta->req_path);
    if (!strcmp(req_path, "/api/login")) {
        http_add_header(&ta->resp_headers, "Content-Type", "application/json");
    }
    else {
        http_add_header(&ta->resp_headers, "Content-Type", "text/plain");
    }
    return send_response(ta);
}

/* Send Not Found response. */
static bool
send_not_found(struct http_transaction *ta)
{
    return send_error(ta, HTTP_NOT_FOUND, "File %s not found", 
        bufio_offset2ptr(ta->client->bufio, ta->req_path));
}

/* A start at assigning an appropriate mime type.  Real-world 
 * servers use more extensive lists such as /etc/mime.types
 */
static const char *
guess_mime_type(char *filename)
{
    char *suffix = strrchr(filename, '.');
    if (suffix == NULL)
        return "text/plain";

    if (!strcasecmp(suffix, ".html"))
        return "text/html";

    if (!strcasecmp(suffix, ".gif"))
        return "image/gif";

    if (!strcasecmp(suffix, ".png"))
        return "image/png";

    if (!strcasecmp(suffix, ".jpg"))
        return "image/jpeg";

    if (!strcasecmp(suffix, ".js"))
        return "text/javascript";
    
    if (!strcasecmp(suffix, ".css"))
        return "text/css";
    
    if (!strcasecmp(suffix, ".mp4"))
        return "video/mp4";

    return "text/plain";
}

/* Handle HTTP transaction for static files. */
static bool
handle_static_asset(struct http_transaction *ta, char *basedir)
{
    //check for range header
    char fname[PATH_MAX];
    printf(basedir);
    char *req_path = bufio_offset2ptr(ta->client->bufio, ta->req_path);
    if (req_path == NULL) {
        return false;
    }
    // if you find ../ in req_path send permission denied
    if (strstr(req_path, "..")) {
        return send_error(ta, HTTP_NOT_FOUND, "Not found.");
    }
    // The code below is vulnerable to an attack.  Can you see
    // which?  Fix it to avoid indirect object reference (IDOR) attacks.
    snprintf(fname, sizeof fname, "%s%s", basedir, req_path);
    if (html5_fallback && strcmp(req_path, "/") == 0) {
        snprintf(fname, sizeof fname, "%s%s", basedir, "/index.html");
    }
    
    if (access(fname, R_OK)) {
        if (errno == EACCES)
            return send_error(ta, HTTP_PERMISSION_DENIED, "Permission denied.");
        else {
            if (html5_fallback) {
                snprintf(fname, sizeof fname, "%s%s", basedir, "/index.html");
            }
            else {
                // fprintf(stderr, req_path);
                return send_not_found(ta);
            }
        }
    }

    // Determine file size
    struct stat st;
    int rc = stat(fname, &st);
    if (rc == -1)
        return send_error(ta, HTTP_INTERNAL_ERROR, "Could not stat file.");

    int filefd = open(fname, O_RDONLY);
    if (filefd == -1) {
        // html5 fallback
        return send_not_found(ta);
    }

    ta->resp_status = HTTP_OK;
    http_add_header(&ta->resp_headers, "Content-Type", "%s", guess_mime_type(fname));
    if (strcmp(guess_mime_type(fname), "video/mp4") == 0) {
        http_add_header(&ta->resp_headers, "Accept-Ranges", "bytes");
        if(ta->exist) {
            ta->resp_status = HTTP_PARTIAL_CONTENT;
            // fprintf(stderr, "\n%d\n", ta->vidend);
            if (ta->vidend != -1) {
                add_content_length(&ta->resp_headers, ta->vidend - ta->vidstart + 1);
                http_add_header(&ta->resp_headers, "Content-Range", "bytes %d-%d/%d", ta->vidstart, ta->vidend, st.st_size);
            }
            else {
                add_content_length(&ta->resp_headers, st.st_size - ta->vidstart);
                http_add_header(&ta->resp_headers, "Content-Range", "bytes %d-%d/%d", ta->vidstart, st.st_size - 1, st.st_size);
            }
        }
    }
    off_t from = 0, to = st.st_size - 1;
    off_t content_length = to + 1 - from;

    if(!ta->exist) {
        add_content_length(&ta->resp_headers, content_length);
    }
    else {
        from = ta->vidstart;
        if (ta->vidend != -1) {
            to = ta->vidend;
        }
    }
    // fprintf(stderr, "\nh\n");
    bool success = send_response_header(ta);
    // fprintf(stderr, "\nh\n");
    if (!success)
        goto out;

    // sendfile may send fewer bytes than requested, hence the loop
    while (success) {
        // fprintf(stderr, "%ld\n", to);
        success = bufio_sendfile(ta->client->bufio, filefd, &from, to + 1 - from) > 0;
    }

out:
    close(filefd);
    return success;
}

static bool validate_cookie(struct http_transaction* ta, char* entire_cookie) {
    
    jwt_t* ymtoken;
    while(*entire_cookie == ' ' || *entire_cookie == '\t') { //skip white space
        entire_cookie++;
    }
    if (!strstr(entire_cookie, "auth_token=")) 
    {
        return false;
    }
    while (entire_cookie != NULL) {
        if(!STARTS_WITH(entire_cookie, "auth_token=")) {
            // send_error(ta, HTTP_PERMISSION_DENIED, "Bad/Missing Token");
            entire_cookie++;
        }
        else {
            break;
        }
    }
    if (!entire_cookie) {
        return false;
    }
    // fprintf(stderr, "checkpoint 1\n");
    
    char* encoded = entire_cookie + 11;

    int rc = jwt_decode(&ymtoken, encoded, 
    (unsigned char *)SECRET_IN_CODE, 
    strlen(SECRET_IN_CODE));
    // fprintf(stderr, "checkpoint 2\n");
    //check token signature not valid
    if (rc) {
        //tok_valid = true;
        //send_error(ta, HTTP_PERMISSION_DENIED, "Bad Token");
        return false;
    }

    char *grants = jwt_get_grants_json(ymtoken, NULL); // NULL means all
    // fprintf(stderr, "\n%s\n", grants);
    // fprintf(stderr, "checkpoint 3\n");
    if (grants == NULL) {
        //send error message
        // send_error(ta, HTTP_PERMISSION_DENIED, "Bad Grants");
        return false;
    }
    
    // an example of how to use Jansson
    json_error_t error;
    json_t *jgrants = json_loadb(grants, strlen(grants), 0, &error);

    json_int_t* exp, iat;
    const char *sub;
    rc = json_unpack(jgrants, "{s:I, s:I, s:s}", 
    "exp", &exp, "iat", &iat, "sub", &sub);

    const char* username = jwt_get_grant(ymtoken, "sub");
    if (strcmp(username, "user0") != 0) {
        send_error(ta, HTTP_PERMISSION_DENIED, "Incorrect information");
        return false;
    }
    time_t now = time(NULL);
    rc = jwt_get_grant_int(ymtoken, "iat");
    long exp_value= jwt_get_grant_int(ymtoken, "exp");

    // int64_t exp_val = (int64_t) exp;
    //int64_t iat_val = (int64_t)iat;
    
    //check token not expired
    now = time(NULL);
    if (now - exp_value <= token_expiration_time){
        return true;
    }else {
        send_error(ta, HTTP_PERMISSION_DENIED, "Token Expired");
        return false;
    }
}

static bool
handle_api(struct http_transaction *ta)
{
    
    if (ta->req_method == HTTP_POST) {
        char *req_path = bufio_offset2ptr(ta->client->bufio, ta->req_path);
        if (STARTS_WITH(req_path, "/api/login")) {
            char *body = bufio_offset2ptr(ta->client->bufio, ta->req_body);
            json_t* json_obj = json_loadb(body, ta->req_content_len, 0, NULL);
            if (json_obj == NULL) { //error check
                return send_error(ta, HTTP_BAD_REQUEST, "Could not load JSON");
            }
            
            json_t* attempted_user = json_object_get(json_obj, "username");
            json_t* attempted_pwd = json_object_get(json_obj, "password");
            const char* a_user = json_string_value(attempted_user);
            const char* a_pwd = json_string_value(attempted_pwd);
            if (!a_pwd || !a_user) {
                return send_error(ta, HTTP_PERMISSION_DENIED, "Wrong user or pass\n");
            }
            int check_pwd = strcmp(a_pwd, "thepassword");
            int check_user = strcmp(a_user, "user0");
            
            if (check_pwd == 0 && check_user == 0){ //correct
                is_auth = true;

                jwt_t *mytoken;
                int rc = jwt_new(&mytoken);

                //add grants
                rc = jwt_add_grant(mytoken, "sub", "user0");
                time_t now = time(NULL);
                rc = jwt_add_grant_int(mytoken, "iat", now);
                long exp_value = token_expiration_time;
                rc = jwt_add_grant_int(mytoken, "exp", now);

                //auth-token=sdjhsdgjtrdfhdrjhgersbd
                rc = jwt_set_alg(mytoken, JWT_ALG_HS256,
                (unsigned char *)SECRET_IN_CODE, 
                strlen(SECRET_IN_CODE));

                char *encoded = jwt_encode_str(mytoken); //encoded using HMAC
                ta->cookie = encoded; //add cookie to ta struct
                http_add_header(&ta->resp_headers, "Set-Cookie", "auth_token=%s; Path=/; Max-Age=%ld; HttpOnly", encoded, exp_value);

                char *grants = jwt_get_grants_json(mytoken, NULL); // NULL means all
                rc = send_error(ta, HTTP_OK, grants);

                return rc; 
            }
            else {
                // fprintf(stderr, "%s", (char*)ta);
                return send_error(ta, HTTP_PERMISSION_DENIED, "Wrong user or pass\n");
            }
            //hexdump(body, ta->req_content_len);
            //printf("end");
        }
        else if (STARTS_WITH(req_path, "/api/logout")){
            //clear cookie
            
            http_add_header(&ta->resp_headers, "Content-Type", "application/json");

            //fmt: <cookie-name>=<cookie-value>; Path=<path-value>; Max-Age=<number>; HttpOnly
            //http_add_header(&ta->resp_headers, "Set-Cookie", "{s=s; s=s; s=I; s}", "auth token", &encoded, "Path", "/", "Max-Age", exp_value, "HttpOnly");
            http_add_header(&ta->resp_headers, "Set-Cookie", "auth_token=%s; Path=/; Max-Age=%lf; HttpOnly", &ta->cookie, 0);
            ta->cookie = NULL;
            ta->resp_status = HTTP_OK;
            return send_response(ta);


        }
        else { //error just in case?

        }
    }
    else if (ta->req_method == HTTP_GET){
        
        char *req_path = bufio_offset2ptr(ta->client->bufio, ta->req_path);
        // fprintf(stderr, req_path);
        
        if (strcmp(req_path, "/api/login") == 0) {
            char* entire_cookie = ta->cookie;

            if (!entire_cookie) {
                return send_error(ta, HTTP_OK, "{}");
            }
            else if (validate_cookie(ta, entire_cookie)) {
                jwt_t* ymtoken;
                char* encoded = entire_cookie + 11;
                jwt_decode(&ymtoken, encoded, 
                (unsigned char *)SECRET_IN_CODE, 
                strlen(SECRET_IN_CODE));
                char *grants = jwt_get_grants_json(ymtoken, NULL); // NULL means all
                http_add_header(&ta->resp_headers, "Content-Type", "application/json");
                buffer_appends(&ta->resp_body, grants);
                buffer_appends(&ta->resp_body, CRLF);
                
                ta->resp_status = HTTP_OK;
                return send_response(ta);;
            }
            else {
                send_error(ta, HTTP_OK, "{}");
                return false;
            } 
        }
        //hexdump(body, ta->req_content_len);
        //printf("end");
        else if(STARTS_WITH(req_path, "/api/video")){
            DIR *root_dir =  opendir(server_root);
           
            struct dirent *directory;
            json_t* json_arr = json_array();
            while ((directory = readdir(root_dir)) != NULL) {
                // array of json objects for videos
                char* d_name_str = directory->d_name;
                char * d = strstr(d_name_str, ".mp4");
                if(d){
                    struct stat stat_file;
                    char fname[PATH_MAX];
                    snprintf(fname, sizeof fname, "%s/%s", server_root, directory->d_name);
                    if (stat(fname, &stat_file) == -1) {
                        closedir(root_dir);
                        perror("stat");
                        exit(EXIT_FAILURE);
                    }
                    int file_size = stat_file.st_size;

                    // create json object to add to overall list
                    json_t* elem = json_object();
                    json_object_set_new(elem, "size", json_integer(file_size));
                    json_object_set_new(elem, "name", json_string(directory->d_name));
                    json_array_append_new(json_arr, elem);                    
                }
            }
            
            buffer_appends(&ta->resp_body, json_dumps(json_arr, 0));
            http_add_header(&ta->resp_headers, "Content-Type", "application/json");
            ta->resp_status = HTTP_OK;
            closedir(root_dir);
            return send_response(ta);
        }
        else{ 
            return send_error(ta, HTTP_NOT_FOUND, "API not implemented");
        }
    }
    return send_error(ta, HTTP_NOT_IMPLEMENTED, "Method not implemented");
}

/* Set up an http client, associating it with a bufio buffer. */
void 
http_setup_client(struct http_client *self, struct bufio *bufio)
{
    self->bufio = bufio;
}

/* Handle a single HTTP transaction.  Returns true on success. */
bool
http_handle_transaction(struct http_client *self)
{
    struct http_transaction ta;
    memset(&ta, 0, sizeof ta);
    ta.client = self;
    ta.exist = false;
    if (!http_parse_request(&ta))
        return false;

    if (!http_process_headers(&ta))
        return false;
    bool http1_1 = ta.req_version == HTTP_1_1;
    if (ta.req_content_len > 0) {
        int rc = bufio_read(self->bufio, ta.req_content_len, &ta.req_body);
        if (rc != ta.req_content_len)
            return false;

        // To see the body, use this:
        // char *body = bufio_offset2ptr(ta.client->bufio, ta.req_body);
        // hexdump(body, ta.req_content_len);
    }

    buffer_init(&ta.resp_headers, 1024);
    http_add_header(&ta.resp_headers, "Server", "CS3214-Personal-Server");
    buffer_init(&ta.resp_body, 0);

    char *req_path = bufio_offset2ptr(ta.client->bufio, ta.req_path);
    
    if (STARTS_WITH(req_path, "/api")) {
        handle_api(&ta);
    } else
    if (STARTS_WITH(req_path, "/private")) {
        if (ta.cookie != NULL && validate_cookie(&ta, ta.cookie)) {
            handle_static_asset(&ta, server_root);
        }else{
            send_error(&ta, HTTP_PERMISSION_DENIED, "Authentication failed.\n");
            
        }
    } else {
        handle_static_asset(&ta, server_root);
    }

    buffer_delete(&ta.resp_headers);
    buffer_delete(&ta.resp_body);

    return http1_1;
}
