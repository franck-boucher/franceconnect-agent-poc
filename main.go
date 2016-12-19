// Copyright (C) 2016  SICTIAM
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

var (
	mongoURI       = flag.String("mongo-uri", "localhost", "MongoDB dial URI")
	listen         = flag.String("listen", ":http", "Address on which to listen")
	ozwilloBaseURI = flag.String("ozwillo", "https://accounts.ozwillo-preprod.eu", "Base URI of the Ozwillo Kernel")
	clientId       = flag.String("client_id", "", "Client ID for FranceConnect Agent (both at Ozwillo and FranceConnect sides)")
	clientSecret   = flag.String("client_secret", "", "Client secret for FranceConnect Agent (both at Ozwillo and FranceConnect sides)")
	fcaRedirectURI = flag.String("fcaRedirectUri", "https://fcagent.integ01.dev-franceconnect.fr/oidc_callback", "Redirect URI for FranceConnect Agent")
)

var (
	fcaRedirectURL *url.URL
	session        *mgo.Session
)
var (
	client = &http.Client{
		// See https://blog.cloudflare.com/the-complete-guide-to-golang-net-http-timeouts/
		Timeout: 5 * time.Minute,
	}
)

type state struct {
	Id        string    `json:"-" bson:"_id"`
	State     string    `json:"state,omitempty"`
	Scope     string    `json:"scope"`
	AcrValues string    `json:"acr_values,omitempty"`
	Nonce     string    `json:"nonce,omitempty"`
	ExpiresAt time.Time `json:"-" bson:"expires_at"`
}

type httpError interface {
	http.Handler
	error
}

type simpleError struct {
	Status int
	Header http.Header
	Body   string
}

func (err *simpleError) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	for k, v := range err.Header {
		w.Header()[k] = v
	}
	if err.Body != "" {
		http.Error(w, err.Body, err.Status)
	} else {
		w.WriteHeader(err.Status)
	}
}

func (err *simpleError) Error() string {
	var b bytes.Buffer
	fmt.Fprintf(&b, "Status: %v", err.Status)
	err.Header.Write(&b)
	return b.String()
}

var _ httpError = &simpleError{}

type redirectError string

func (err redirectError) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, string(err), http.StatusSeeOther)
}

func (err redirectError) Error() string {
	return "Redirect to " + string(err)
}

var _ httpError = redirectError("")

type oauthError string

func (err oauthError) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(map[string]string{"error": string(err)})
}

func (err oauthError) Error() string {
	return "OAuth error " + string(err)
}

var _ httpError = oauthError("")

type redirectUri struct {
	u  url.URL
	qs url.Values
}

func NewRedirectUri() *redirectUri {
	return &redirectUri{
		u:  *fcaRedirectURL,
		qs: fcaRedirectURL.Query(),
	}
}

func (ruri *redirectUri) SetState(state string) {
	ruri.qs.Set("state", state)
}

func (ruri *redirectUri) SetCode(code string) {
	ruri.qs.Set("code", code)
}

func (ruri *redirectUri) SetError(error string) {
	ruri.qs.Set("error", error)
}
func (ruri *redirectUri) SetErrorDesc(error, desc, uri string) {
	ruri.SetError(error)
	if desc != "" {
		ruri.qs.Set("error_description", desc)
	}
	if uri != "" {
		ruri.qs.Set("error_uri", uri)
	}
}

func (ruri *redirectUri) String() string {
	ruri.u.RawQuery = ruri.qs.Encode()
	return ruri.u.String()
}

func main() {
	flag.Parse()

	if *clientId == "" || *clientSecret == "" {
		log.Fatalln("client_id and client_server must be set")
	}

	var err error
	fcaRedirectURL, err = url.ParseRequestURI(*fcaRedirectURI)
	if err != nil {
		log.Fatalln("fcaRedirectURI: ", err)
	} else if !fcaRedirectURL.IsAbs() {
		log.Fatalln("fcaRedirectURI: not absolute")
	}

	session, err = mgo.Dial(*mongoURI)
	if err != nil {
		log.Fatalln(err)
	}

	// XXX: Can't use ExpireAfter:0 as that's the default value and wouldn't enable TTL on the index
	_ = session.DB("").C("state").EnsureIndex(mgo.Index{Key: []string{"expires_at"}, ExpireAfter: 1, Background: true})

	server := http.Server{
		Addr:    *listen,
		Handler: http.HandlerFunc(dispatch),
		// See https://blog.cloudflare.com/the-complete-guide-to-golang-net-http-timeouts/
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	err = server.ListenAndServe()
	log.Fatalln(err)
}

func dispatch(w http.ResponseWriter, r *http.Request) {
	var err error
	switch r.URL.Path {
	case "/user/authorize":
		err = authorizeEndpoint(w, r)
	case "/oidc_callback":
		err = oidcCallback(w, r)
	case "/user/token":
		err = tokenEndpoint(w, r)
	case "/api/userinfo":
		err = userinfoEndpoint(w, r)
	default:
		http.NotFound(w, r)
		return
	}
	if herr, ok := err.(httpError); ok {
		herr.ServeHTTP(w, r)
		return
	}
	if err != nil {
		log.Println("Error serving request to", r.RequestURI, err)
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func checkMethod(r *http.Request, allowedMethod string) error {
	if r.Method == allowedMethod {
		return nil
	}
	return &simpleError{
		Status: http.StatusMethodNotAllowed,
		Header: http.Header{
			"Allow": {allowedMethod},
		},
	}
}

func authorizeEndpoint(w http.ResponseWriter, r *http.Request) error {
	if err := checkMethod(r, "GET"); err != nil {
		return err
	}
	qs := r.URL.Query()
	if qs.Get("client_id") != *clientId {
		return &simpleError{Status: http.StatusBadRequest, Body: "Unknown client_id"}
	}
	if qs.Get("redirect_uri") != *fcaRedirectURI {
		return &simpleError{Status: http.StatusBadRequest, Body: "Invalid redirect_uri"}
	}

	errorRedirect := NewRedirectUri()

	s := qs.Get("state")
	errorRedirect.SetState(s)

	responseType := qs.Get("response_type")
	if responseType != "code" {
		errorRedirect.SetErrorDesc("unsupported_response_type", "Only 'code' is supported.", "")
		return redirectError(errorRedirect.String())
	}
	responseMode := qs.Get("response_mode")
	if responseMode != "" && responseMode != "query" {
		errorRedirect.SetErrorDesc("invalid_param", "response_mode", "")
		return redirectError(errorRedirect.String())
	}

	if _, ok := qs["request"]; ok {
		errorRedirect.SetError("request_node_supported")
		return redirectError(errorRedirect.String())
	}
	if _, ok := qs["request_uri"]; ok {
		errorRedirect.SetError("request_uri_not_supported")
		return redirectError(errorRedirect.String())
	}

	// Replace scope, state and redirect_uri; remove acr_values and id_token_hint
	scope := qs.Get("scope")
	ozwilloScopes := make([]string, 0, 5)
	for _, s := range strings.Fields(scope) {
		switch s {
		case "openid", "profile", "email", "address", "phone":
			// TODO: what about offline_access?
			ozwilloScopes = append(ozwilloScopes, s)
		}
	}
	qs.Set("scope", strings.Join(ozwilloScopes, " "))

	ozwilloState, err := json.Marshal(state{
		State:     s,
		Scope:     scope,
		AcrValues: qs.Get("acr_values"),
		Nonce:     qs.Get("nonce"),
	})
	if err != nil {
		return &simpleError{Status: http.StatusInternalServerError}
	}
	qs.Set("state", string(ozwilloState))
	qs.Del("acr_values")
	qs.Del("id_token_hint")

	qs.Set("redirect_uri", getRedirectUri(r))

	http.Redirect(w, r, *ozwilloBaseURI+"/a/auth?"+qs.Encode(), http.StatusSeeOther)
	return nil
}

func getBaseUri(r *http.Request) string {
	proto := r.Header.Get("X-Forwarded-Proto")
	if proto == "" {
		proto = "http"
	}
	return proto + "://" + r.Host
}

func getRedirectUri(r *http.Request) string {
	return getBaseUri(r) + "/oidc_callback"
}

func oidcCallback(w http.ResponseWriter, r *http.Request) error {
	if err := checkMethod(r, "GET"); err != nil {
		return err
	}
	qs := r.URL.Query()
	var decodedState state
	if err := json.Unmarshal([]byte(qs.Get("state")), &decodedState); err != nil {
		return &simpleError{Status: http.StatusInternalServerError}
	}

	redirectUri := NewRedirectUri()
	redirectUri.SetState(decodedState.State)

	if code := qs.Get("code"); code != "" {
		// store 'decodedState' in DB keyed by 'code' (to be retrieved by tokenEndpoint)
		// 1 minute is the default Ozwillo expiration delay for authorization codes
		decodedState.Id = "code:" + code
		decodedState.ExpiresAt = time.Now().Add(1 * time.Minute)
		if err := session.DB("").C("state").Insert(decodedState); err != nil {
			redirectUri.SetError("server_error")
		} else {
			redirectUri.SetCode(code)
		}
	} else if error := qs.Get("error"); error != "" {
		redirectUri.SetErrorDesc(error, qs.Get("error_description"), qs.Get("error_uri"))
	} else {
		redirectUri.SetError("server_error")
	}
	http.Redirect(w, r, redirectUri.String(), http.StatusSeeOther)
	return nil
}

func tokenEndpoint(w http.ResponseWriter, r *http.Request) error {
	if err := checkMethod(r, "POST"); err != nil {
		return err
	}
	if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		return &simpleError{Status: http.StatusUnsupportedMediaType}
	}
	if r.PostFormValue("client_id") != *clientId || r.PostFormValue("client_secret") != *clientSecret {
		return oauthError("invalid_client")
	}
	if r.PostFormValue("grant_type") != "authorization_code" {
		return oauthError("unsupported_grant_type")
	}
	if r.PostFormValue("redirect_uri") != *fcaRedirectURI {
		return oauthError("invalid_request")
	}
	code := r.PostFormValue("code")

	var s state
	if _, err := session.DB("").C("state").FindId("code:"+code).Apply(mgo.Change{Remove: true}, &s); err == mgo.ErrNotFound {
		return oauthError("invalid_grant")
	} else if err != nil {
		log.Println("Error retrieving state from DB", err)
		return &simpleError{Status: http.StatusInternalServerError}
	}

	req, err := http.NewRequest("POST", *ozwilloBaseURI+"/a/token", strings.NewReader(url.Values{
		"grant_type":   {"authorization_code"},
		"redirect_uri": {getRedirectUri(r)},
		"code":         {code},
	}.Encode()))
	if err != nil {
		log.Println("Error creating request to Token endpoint:", err)
		return &simpleError{Status: http.StatusInternalServerError}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(*clientId, *clientSecret)
	resp, err := client.Do(req)
	if err != nil {
		log.Println("Error calling Token endpoint:", err)
		return &simpleError{Status: http.StatusBadGateway}
	}
	defer resp.Body.Close()
	if err := checkStatus(resp, "Token"); err != nil {
		return err
	}

	var tokenResponse struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"tokenType"`
		ExpiresIn   uint16 `json:"expires_in"`
		IdToken     string `json:"id_token"`
	}
	if err = json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		log.Println("Error parsing Token response:", err)
		return &simpleError{Status: http.StatusInternalServerError}
	}

	// store state in DB keyed by tokenResponse.accessToken (to be retrieved by userinfoEndpoint)
	s.Id = "token:" + tokenResponse.AccessToken
	s.ExpiresAt = time.Now().Add(time.Duration(tokenResponse.ExpiresIn) * time.Second)
	if err := session.DB("").C("state").Insert(s); err != nil {
		return &simpleError{Status: http.StatusInternalServerError}
	}

	// re-sign id_token
	claims, err := parseIdToken(tokenResponse.IdToken)
	if err != nil {
		log.Println("Malformed ID Token from Ozwillo:", err)
		return &simpleError{Status: http.StatusBadGateway}
	}

	claims["iss"] = getBaseUri(r)
	delete(claims, "app_admin")
	delete(claims, "app_user")
	tokenResponse.IdToken, err = makeJwt(claims)
	if err != nil {
		log.Println("Error signing ID Token:", err)
		return &simpleError{Status: http.StatusInternalServerError}
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(tokenResponse)
	if err != nil {
		log.Println("Error serializing augmented UserInfo:", err)
		return &simpleError{Status: http.StatusInternalServerError}
	}
	return nil
}

func checkStatus(resp *http.Response, endpointName string) error {
	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusServiceUnavailable:
		return &simpleError{
			Status: http.StatusServiceUnavailable,
			Header: http.Header{
				"Retry-After": resp.Header["Retry-After"],
			},
		}
	case http.StatusUnauthorized, http.StatusForbidden:
		return &simpleError{
			Status: resp.StatusCode,
			Header: http.Header{
				"Www-Authenticate": resp.Header["Www-Authenticate"],
			},
		}
	default:
		log.Println(endpointName, "endpoint returned error:", resp.StatusCode, resp.Status)
		return &simpleError{Status: http.StatusBadGateway}
	}
}

func parseIdToken(idToken string) (map[string]interface{}, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("expected 3 parts, got %d\n", len(parts))
	}
	// XXX: we do trust Ozwillo and do not verify the signature or even the ID Token claims
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	claims := make(map[string]interface{})
	if err = json.Unmarshal(payload, claims); err != nil {
		return nil, err
	}
	return claims, nil
}

func userinfoEndpoint(w http.ResponseWriter, r *http.Request) error {
	if err := checkMethod(r, "GET"); err != nil {
		return err
	}

	// Similar logic than in http.Request.BasicAuth()
	authz := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(authz, prefix) {
		return &simpleError{
			Status: http.StatusUnauthorized,
			Header: http.Header{
				"Www-Authenticate": {"Bearer"},
			},
		}
	}
	token := authz[len(prefix):]

	var s state
	if err := session.DB("").C("state").FindId("token:" + token).One(&s); err == mgo.ErrNotFound {
		return &simpleError{
			Status: http.StatusUnauthorized,
			Header: http.Header{
				"Www-Authenticate": {`Bearer error="invalid_token"`},
			},
		}
	} else if err != nil {
		log.Println("Error retrieving 'state' from Mongo:", err)
		return &simpleError{Status: http.StatusInternalServerError}
	}

	req, err := http.NewRequest("POST", *ozwilloBaseURI+"/a/userinfo", nil)
	if err != nil {
		log.Println("Error creating request to UserInfo endpoint:", err)
		return &simpleError{Status: http.StatusInternalServerError}
	}
	req.Header.Add("Authorization", "Bearer "+token)
	req.Header.Add("Accept", "application/json") // prefer JSON to JWT
	resp, err := client.Do(req)
	if err != nil {
		log.Println("Error calling UserInfo endpoint:", err)
		return &simpleError{Status: http.StatusBadGateway}
	}
	defer resp.Body.Close()
	if err := checkStatus(resp, "UserInfo"); err != nil {
		return err
	}

	var userinfo map[string]interface{}
	if err = json.NewDecoder(resp.Body).Decode(&userinfo); err != nil {
		log.Println("Error parsing UserInfo response:", err)
		return &simpleError{Status: http.StatusInternalServerError}
	}

	sub, ok := userinfo["sub"].(string)
	if !ok {
		log.Println("Bad UserInfo response, missing 'sub' or not a string:", userinfo)
		return &simpleError{Status: http.StatusInternalServerError}
	}

	var attrs map[string]interface{}
	if err = session.DB("").C("attributs").FindId(sub).Select(bson.M{"_id": 0}).One(&attrs); err != nil && err != mgo.ErrNotFound {
		log.Println("Error querying attributes for user", sub, ":", err)
		return &simpleError{Status: http.StatusInternalServerError}
	}

	userinfo["birthplace"] = attrs["birthplace"]
	userinfo["birthcountry"] = attrs["birthcountry"]
	delete(attrs, "birthplace")
	delete(attrs, "birthcountry")

	var claimNames map[string]string
	var claims map[string]interface{}
	for _, v := range strings.Fields(s.AcrValues) {
		claimNames[v] = "srv1"
		claims[v] = attrs[v]
	}
	signedClaims, err := makeJwt(claims)
	if err != nil {
		return err
	}
	userinfo["_claim_names"] = claimNames
	userinfo["_claim_sources"] = map[string]string{
		"src1": signedClaims,
	}

	w.Header().Add("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(userinfo)
	if err != nil {
		log.Println("Error serializing augmented UserInfo:", err)
		return &simpleError{Status: http.StatusInternalServerError}
	}
	return nil
}

func makeJwt(claims map[string]interface{}) (string, error) {
	// XXX: this is `{"typ":"JWT","alg":"HS256"}` encoded as base64url (from jwt.io), followed by a dot.
	const header = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9."

	buf := bytes.NewBufferString(header)
	base64Encoder := base64.NewEncoder(base64.RawURLEncoding, buf)
	jsonEncoder := json.NewEncoder(base64Encoder)
	jsonEncoder.SetEscapeHTML(false)
	if err := jsonEncoder.Encode(claims); err != nil {
		return "", err
	}
	if err := base64Encoder.Close(); err != nil {
		return "", err
	}

	sig := hmac.New(sha256.New, []byte(*clientSecret)).Sum(buf.Bytes())
	buf.WriteRune('.')
	buf.Write(sig)

	return buf.String(), nil
}
