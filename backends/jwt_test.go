package backends

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/iegomez/mosquitto-go-auth/hashing"
	log "github.com/sirupsen/logrus"
	. "github.com/smartystreets/goconvey/convey"
)

var username = "test"

//Hash generated by the pw utility
var userPassHash = "PBKDF2$sha512$100000$os24lcPr9cJt2QDVWssblQ==$BK1BQ2wbwU1zNxv3Ml3wLuu5//hPop3/LvaPYjjCwdBvnpwusnukJPpcXQzyyjOlZdieXTx6sXAcX4WnZRZZnw=="

var jwtSecret = "some_jwt_secret"

// Generate the token.
var now = time.Now()
var nowSecondsSinceEpoch = now.Unix()
var expSecondsSinceEpoch int64 = nowSecondsSinceEpoch + int64(time.Hour*24/time.Second)

var jwtToken = jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
	"iss":      "jwt-test",
	"aud":      "jwt-test",
	"nbf":      nowSecondsSinceEpoch,
	"exp":      expSecondsSinceEpoch,
	"sub":      "user",
	"username": username,
})

var wrongJwtToken = jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
	"iss":      "jwt-test",
	"aud":      "jwt-test",
	"nbf":      nowSecondsSinceEpoch,
	"exp":      expSecondsSinceEpoch,
	"sub":      "user",
	"username": "wrong_user",
})

var expiredToken = jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
	"iss":      "jwt-test",
	"aud":      "jwt-test",
	"nbf":      nowSecondsSinceEpoch,
	"exp":      nowSecondsSinceEpoch - int64(time.Hour*24/time.Second),
	"sub":      "user",
	"username": username,
})

var tkOptions = tokenOptions{
	secret:    jwtSecret,
	userField: "Username",
}

func TestJWTClaims(t *testing.T) {
	Convey("When getting claims", t, func() {
		Convey("Correct token should give no error", func() {
			token, err := jwtToken.SignedString([]byte(jwtSecret))
			So(err, ShouldBeNil)

			_, err = getJWTClaims(jwtSecret, token, false)
			So(err, ShouldBeNil)
		})

		Convey("A token signed with a different secret should give an error", func() {
			token, err := jwtToken.SignedString([]byte("wrong-secret"))
			So(err, ShouldBeNil)

			_, err = getJWTClaims(jwtSecret, token, false)
			So(err, ShouldNotBeNil)
		})

		Convey("Wrong user token should give no error", func() {
			token, err := wrongJwtToken.SignedString([]byte(jwtSecret))
			So(err, ShouldBeNil)

			_, err = getJWTClaims(jwtSecret, token, false)
			So(err, ShouldBeNil)
		})

		Convey("Expired token should give an error when getting claims", func() {
			token, err := expiredToken.SignedString([]byte(jwtSecret))
			So(err, ShouldBeNil)

			_, err = getJWTClaims(jwtSecret, token, false)
			So(err, ShouldNotBeNil)
		})

		Convey("When skipping expiration, expired token should not give an error", func() {
			token, err := expiredToken.SignedString([]byte(jwtSecret))
			So(err, ShouldBeNil)

			_, err = getJWTClaims(jwtSecret, token, true)
			So(err, ShouldBeNil)
		})
	})
}

func TestJsJWTChecker(t *testing.T) {
	authOpts := make(map[string]string)

	authOpts["jwt_js_user_script_path"] = "../test-files/jwt/user_script.js"
	authOpts["jwt_js_superuser_script_path"] = "../test-files/jwt/superuser_script.js"
	authOpts["jwt_js_acl_script_path"] = "../test-files/jwt/acl_script.js"

	Convey("Creating a js checker should succeed", t, func() {
		checker, err := NewJsJWTChecker(authOpts, tkOptions)
		So(err, ShouldBeNil)

		userResponse := checker.GetUser("correct")
		So(userResponse, ShouldBeTrue)

		userResponse = checker.GetUser("bad")
		So(userResponse, ShouldBeFalse)

		superuserResponse := checker.GetSuperuser("admin")
		So(superuserResponse, ShouldBeTrue)

		superuserResponse = checker.GetSuperuser("non-admin")
		So(superuserResponse, ShouldBeFalse)

		aclResponse := checker.CheckAcl("correct", "test/topic", "id", 1)
		So(aclResponse, ShouldBeTrue)

		aclResponse = checker.CheckAcl("incorrect", "test/topic", "id", 1)
		So(userResponse, ShouldBeFalse)

		aclResponse = checker.CheckAcl("correct", "bad/topic", "id", 1)
		So(aclResponse, ShouldBeFalse)

		aclResponse = checker.CheckAcl("correct", "test/topic", "wrong-id", 1)
		So(aclResponse, ShouldBeFalse)

		aclResponse = checker.CheckAcl("correct", "test/topic", "id", 2)
		So(aclResponse, ShouldBeFalse)

		Convey("Tokens may be pre-parsed and passed to the scripts", func() {
			jsTokenOptions := tokenOptions{
				parseToken: true,
				secret:     jwtSecret,
				userField:  "Username",
			}

			authOpts["jwt_js_user_script_path"] = "../test-files/jwt/parsed_user_script.js"

			checker, err = NewJsJWTChecker(authOpts, jsTokenOptions)
			So(err, ShouldBeNil)

			token, err := jwtToken.SignedString([]byte(jwtSecret))
			So(err, ShouldBeNil)

			userResponse := checker.GetUser(token)
			So(userResponse, ShouldBeTrue)
		})
	})
}

func TestLocalPostgresJWT(t *testing.T) {

	Convey("Creating a token should return a nil error", t, func() {
		token, err := jwtToken.SignedString([]byte(jwtSecret))
		So(err, ShouldBeNil)

		// Initialize JWT in local mode.
		authOpts := make(map[string]string)
		authOpts["jwt_mode"] = "local"
		authOpts["jwt_db"] = "postgres"
		authOpts["jwt_secret"] = jwtSecret
		authOpts["jwt_userfield"] = "Username"
		authOpts["jwt_userquery"] = "select count(*) from test_user where username = $1 limit 1"

		// Give necessary postgres options.
		authOpts["jwt_pg_host"] = "localhost"
		authOpts["jwt_pg_port"] = "5432"
		authOpts["jwt_pg_dbname"] = "go_auth_test"
		authOpts["jwt_pg_user"] = "go_auth_test"
		authOpts["jwt_pg_password"] = "go_auth_test"
		authOpts["jwt_pg_superquery"] = "select count(*) from test_user where username = $1 and is_admin = true"
		authOpts["jwt_pg_aclquery"] = "SELECT test_acl.topic FROM test_acl, test_user WHERE test_user.username = $1 AND test_acl.test_user_id = test_user.id AND rw >= $2"

		// Set regular PG options just to create a PG instance and create the records.

		pgAuthOpts := make(map[string]string)
		pgAuthOpts["pg_host"] = "localhost"
		pgAuthOpts["pg_port"] = "5432"
		pgAuthOpts["pg_dbname"] = "go_auth_test"
		pgAuthOpts["pg_user"] = "go_auth_test"
		pgAuthOpts["pg_password"] = "go_auth_test"
		pgAuthOpts["pg_userquery"] = "mock"
		pgAuthOpts["pg_superquery"] = "mock"
		pgAuthOpts["pg_aclquery"] = "mock"

		db, err := NewPostgres(pgAuthOpts, log.DebugLevel, hashing.NewHasher(pgAuthOpts, ""))
		So(err, ShouldBeNil)

		Convey("Given correct option NewJWT returns an instance of jwt backend", func() {
			jwt, err := NewLocalJWTChecker(authOpts, log.DebugLevel, hashing.NewHasher(authOpts, ""), tkOptions)
			So(err, ShouldBeNil)

			//Empty db
			db.DB.MustExec("delete from test_user where 1 = 1")
			db.DB.MustExec("delete from test_acl where 1 = 1")

			//Now test everything.

			insertQuery := "INSERT INTO test_user(username, password_hash, is_admin) values($1, $2, $3) returning id"

			userID := 0

			err = db.DB.Get(&userID, insertQuery, username, userPassHash, true)

			So(err, ShouldBeNil)
			So(userID, ShouldBeGreaterThan, 0)

			Convey("Given a correct token, it should correctly authenticate it", func() {

				authenticated := jwt.GetUser(token)
				So(authenticated, ShouldBeTrue)
			})

			Convey("Given an incorrect token, it should not authenticate it", func() {

				wrongToken, err := wrongJwtToken.SignedString([]byte(jwtSecret))
				So(err, ShouldBeNil)

				authenticated := jwt.GetUser(wrongToken)
				So(authenticated, ShouldBeFalse)

			})

			Convey("Given a token that is admin, super user should pass", func() {
				superuser := jwt.GetSuperuser(token)
				So(superuser, ShouldBeTrue)

				Convey("But disabling superusers by removing superuri should now return false", func() {
					authOpts["jwt_superquery"] = ""
					jwt, err := NewLocalJWTChecker(authOpts, log.DebugLevel, hashing.NewHasher(authOpts, ""), tkOptions)
					So(err, ShouldBeNil)

					superuser := jwt.GetSuperuser(username)
					So(superuser, ShouldBeFalse)
				})
			})

			//Now create some acls and test topics

			strictACL := "test/topic/1"
			singleLevelACL := "test/topic/+"
			hierarchyACL := "test/#"

			clientID := "test_client"

			aclID := 0
			aclQuery := "INSERT INTO test_acl(test_user_id, topic, rw) values($1, $2, $3) returning id"
			err = db.DB.Get(&aclID, aclQuery, userID, strictACL, MOSQ_ACL_READ)
			So(err, ShouldBeNil)

			Convey("Given only strict acl in db, an exact match should work and and inexact one not", func() {

				testTopic1 := `test/topic/1`
				testTopic2 := `test/topic/2`

				tt1 := jwt.CheckAcl(token, testTopic1, clientID, MOSQ_ACL_READ)
				tt2 := jwt.CheckAcl(token, testTopic2, clientID, MOSQ_ACL_READ)

				So(tt1, ShouldBeTrue)
				So(tt2, ShouldBeFalse)

			})

			Convey("Given read only privileges, a pub check should fail", func() {

				testTopic1 := "test/topic/1"
				tt1 := jwt.CheckAcl(token, testTopic1, clientID, MOSQ_ACL_WRITE)
				So(tt1, ShouldBeFalse)

			})

			Convey("Given wildcard subscriptions against strict db acl, acl checks should fail", func() {

				tt1 := jwt.CheckAcl(token, singleLevelACL, clientID, MOSQ_ACL_READ)
				tt2 := jwt.CheckAcl(token, hierarchyACL, clientID, MOSQ_ACL_READ)

				So(tt1, ShouldBeFalse)
				So(tt2, ShouldBeFalse)

			})

			//Now insert single level topic to check against.

			err = db.DB.Get(&aclID, aclQuery, userID, singleLevelACL, MOSQ_ACL_READ)
			So(err, ShouldBeNil)

			Convey("Given a topic not strictly present that matches a db single level wildcard, acl check should pass", func() {
				tt1 := jwt.CheckAcl(token, "test/topic/whatever", clientID, MOSQ_ACL_READ)
				So(tt1, ShouldBeTrue)
			})

			//Now insert hierarchy wildcard to check against.

			err = db.DB.Get(&aclID, aclQuery, userID, hierarchyACL, MOSQ_ACL_READ)
			So(err, ShouldBeNil)

			Convey("Given a topic not strictly present that matches a hierarchy wildcard, acl check should pass", func() {
				tt1 := jwt.CheckAcl(token, "test/what/ever", clientID, MOSQ_ACL_READ)
				So(tt1, ShouldBeTrue)
			})

			Convey("Deleting superuser and acl queries should work fine", func() {

				authOpts["jwt_pg_superquery"] = ""
				authOpts["jwt_pg_aclquery"] = ""

				jwt, err := NewLocalJWTChecker(authOpts, log.DebugLevel, hashing.NewHasher(authOpts, ""), tkOptions)
				So(err, ShouldBeNil)

				Convey("So checking against them should give false and true for any user", func() {

					tt1 := jwt.CheckAcl(token, singleLevelACL, clientID, MOSQ_ACL_READ)
					tt2 := jwt.CheckAcl(token, hierarchyACL, clientID, MOSQ_ACL_READ)

					So(tt1, ShouldBeTrue)
					So(tt2, ShouldBeTrue)

					superuser := jwt.GetSuperuser(token)
					So(superuser, ShouldBeFalse)

				})

			})

			//Empty db
			db.DB.MustExec("delete from test_user where 1 = 1")
			db.DB.MustExec("delete from test_acl where 1 = 1")

			jwt.Halt()
		})

	})

}

func TestLocalMysqlJWT(t *testing.T) {

	Convey("Creating a token should return a nil error", t, func() {
		token, err := jwtToken.SignedString([]byte(jwtSecret))
		So(err, ShouldBeNil)

		// Initialize JWT in local mode.
		authOpts := make(map[string]string)
		authOpts["jwt_mode"] = "local"
		authOpts["jwt_db"] = "mysql"
		authOpts["jwt_secret"] = jwtSecret
		authOpts["jwt_userfield"] = "Username"
		authOpts["jwt_userquery"] = "select count(*) from test_user where username = ? limit 1"

		// Give necessary postgres options.
		authOpts["jwt_mysql_host"] = "localhost"
		authOpts["jwt_mysql_port"] = "3306"
		authOpts["jwt_mysql_dbname"] = "go_auth_test"
		authOpts["jwt_mysql_user"] = "go_auth_test"
		authOpts["jwt_mysql_password"] = "go_auth_test"
		authOpts["jwt_mysql_allow_native_passwords"] = "true"
		authOpts["jwt_mysql_superquery"] = "select count(*) from test_user where username = ? and is_admin = true"
		authOpts["jwt_mysql_aclquery"] = "SELECT test_acl.topic FROM test_acl, test_user WHERE test_user.username = ? AND test_acl.test_user_id = test_user.id AND rw >= ?"

		// Set options for our MySQL instance used to create test records.
		mysqlAuthOpts := make(map[string]string)
		mysqlAuthOpts["mysql_host"] = "localhost"
		mysqlAuthOpts["mysql_port"] = "3306"
		mysqlAuthOpts["mysql_dbname"] = "go_auth_test"
		mysqlAuthOpts["mysql_user"] = "go_auth_test"
		mysqlAuthOpts["mysql_password"] = "go_auth_test"
		mysqlAuthOpts["mysql_allow_native_passwords"] = "true"
		mysqlAuthOpts["mysql_userquery"] = "mock"
		mysqlAuthOpts["mysql_superquery"] = "mock"
		mysqlAuthOpts["mysql_aclquery"] = "mock"

		db, err := NewMysql(mysqlAuthOpts, log.DebugLevel, hashing.NewHasher(mysqlAuthOpts, ""))
		So(err, ShouldBeNil)

		Convey("Given correct option NewJWT returns an instance of jwt backend", func() {
			jwt, err := NewLocalJWTChecker(authOpts, log.DebugLevel, hashing.NewHasher(authOpts, ""), tkOptions)
			So(err, ShouldBeNil)

			//Empty db
			db.DB.MustExec("delete from test_user where 1 = 1")
			db.DB.MustExec("delete from test_acl where 1 = 1")

			//Now test everything.

			insertQuery := "INSERT INTO test_user(username, password_hash, is_admin) values(?, ?, ?)"

			userID := int64(0)

			res, err := db.DB.Exec(insertQuery, username, userPassHash, true)
			So(err, ShouldBeNil)

			userID, err = res.LastInsertId()

			So(err, ShouldBeNil)
			So(userID, ShouldBeGreaterThan, 0)

			Convey("Given a correct token, it should correctly authenticate it", func() {

				authenticated := jwt.GetUser(token)
				So(authenticated, ShouldBeTrue)

			})

			Convey("Given an incorrect token, it should not authenticate it", func() {

				wrongToken, err := wrongJwtToken.SignedString([]byte(jwtSecret))
				So(err, ShouldBeNil)

				authenticated := jwt.GetUser(wrongToken)
				So(authenticated, ShouldBeFalse)

			})

			Convey("Given a token that is admin, super user should pass", func() {
				superuser := jwt.GetSuperuser(token)
				So(superuser, ShouldBeTrue)
				Convey("But disabling superusers by removing superuri should now return false", func() {
					authOpts["jwt_superquery"] = ""
					jwt, err := NewLocalJWTChecker(authOpts, log.DebugLevel, hashing.NewHasher(authOpts, ""), tkOptions)
					So(err, ShouldBeNil)

					superuser := jwt.GetSuperuser(username)
					So(superuser, ShouldBeFalse)
				})
			})

			strictACL := "test/topic/1"
			singleLevelACL := "test/topic/+"
			hierarchyACL := "test/#"

			clientID := "test_client"

			aclID := int64(0)
			aclQuery := "INSERT INTO test_acl(test_user_id, topic, rw) values(?, ?, ?)"
			res, err = db.DB.Exec(aclQuery, userID, strictACL, MOSQ_ACL_READ)
			So(err, ShouldBeNil)
			aclID, err = res.LastInsertId()
			So(err, ShouldBeNil)
			So(aclID, ShouldBeGreaterThan, 0)

			Convey("Given only strict acl in db, an exact match should work and and inexact one not", func() {

				testTopic1 := `test/topic/1`
				testTopic2 := `test/topic/2`

				tt1 := jwt.CheckAcl(token, testTopic1, clientID, MOSQ_ACL_READ)
				tt2 := jwt.CheckAcl(token, testTopic2, clientID, MOSQ_ACL_READ)

				So(tt1, ShouldBeTrue)
				So(tt2, ShouldBeFalse)

			})

			Convey("Given read only privileges, a pub check should fail", func() {

				testTopic1 := "test/topic/1"
				tt1 := jwt.CheckAcl(token, testTopic1, clientID, MOSQ_ACL_WRITE)
				So(tt1, ShouldBeFalse)

			})

			Convey("Given wildcard subscriptions against strict db acl, acl checks should fail", func() {

				tt1 := jwt.CheckAcl(token, singleLevelACL, clientID, MOSQ_ACL_READ)
				tt2 := jwt.CheckAcl(token, hierarchyACL, clientID, MOSQ_ACL_READ)

				So(tt1, ShouldBeFalse)
				So(tt2, ShouldBeFalse)

			})

			//Now insert single level topic to check against.

			_, err = db.DB.Exec(aclQuery, userID, singleLevelACL, MOSQ_ACL_READ)
			So(err, ShouldBeNil)

			Convey("Given a topic not strictly present that matches a db single level wildcard, acl check should pass", func() {
				tt1 := jwt.CheckAcl(token, "test/topic/whatever", clientID, MOSQ_ACL_READ)
				So(tt1, ShouldBeTrue)
			})

			//Now insert hierarchy wildcard to check against.

			_, err = db.DB.Exec(aclQuery, userID, hierarchyACL, MOSQ_ACL_READ)
			So(err, ShouldBeNil)

			Convey("Given a topic not strictly present that matches a hierarchy wildcard, acl check should pass", func() {
				tt1 := jwt.CheckAcl(token, "test/what/ever", clientID, MOSQ_ACL_READ)
				So(tt1, ShouldBeTrue)
			})

			Convey("Deleting superuser and acl queries should work fine", func() {

				authOpts["jwt_mysql_superquery"] = ""
				authOpts["jwt_mysql_aclquery"] = ""

				jwt, err := NewLocalJWTChecker(authOpts, log.DebugLevel, hashing.NewHasher(authOpts, ""), tkOptions)
				So(err, ShouldBeNil)

				Convey("So checking against them should give false and true for any user", func() {

					tt1 := jwt.CheckAcl(token, singleLevelACL, clientID, MOSQ_ACL_READ)
					tt2 := jwt.CheckAcl(token, hierarchyACL, clientID, MOSQ_ACL_READ)

					So(tt1, ShouldBeTrue)
					So(tt2, ShouldBeTrue)

					superuser := jwt.GetSuperuser(token)
					So(superuser, ShouldBeFalse)

				})

			})

			//Empty db
			db.DB.MustExec("delete from test_user where 1 = 1")
			db.DB.MustExec("delete from test_acl where 1 = 1")

			jwt.Halt()

		})

	})

}

func TestJWTAllJsonServer(t *testing.T) {

	topic := "test/topic"
	var acc = int64(1)
	clientID := "test_client"

	token, _ := jwtToken.SignedString([]byte(jwtSecret))
	wrongToken, _ := wrongJwtToken.SignedString([]byte(jwtSecret))

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		httpResponse := &HTTPResponse{
			Ok:    true,
			Error: "",
		}

		var jsonResponse []byte

		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")

		gToken := r.Header.Get("Authorization")
		gToken = strings.TrimPrefix(gToken, "Bearer ")

		if token != gToken {
			httpResponse.Ok = false
			httpResponse.Error = "Wrong token."
		} else {
			switch r.URL.Path {
			case "/user", "/superuser":
				httpResponse.Ok = true
				httpResponse.Error = ""
			case "/acl":
				var data interface{}
				var params map[string]interface{}

				body, _ := ioutil.ReadAll(r.Body)
				defer r.Body.Close()

				err := json.Unmarshal(body, &data)

				if err != nil {
					httpResponse.Ok = false
					httpResponse.Error = "Json unmarshal error"
					break
				}

				params = data.(map[string]interface{})
				paramsAcc := int64(params["acc"].(float64))

				if params["topic"].(string) == topic && params["clientid"].(string) == clientID && paramsAcc <= acc {
					httpResponse.Ok = true
					httpResponse.Error = ""
					break
				}
				httpResponse.Ok = false
				httpResponse.Error = "Acl check failed."
			}
		}

		jsonResponse, err := json.Marshal(httpResponse)
		if err != nil {
			w.Write([]byte("error"))
		}

		w.Write(jsonResponse)

	}))

	defer mockServer.Close()

	authOpts := make(map[string]string)
	authOpts["jwt_mode"] = "remote"
	authOpts["jwt_params_mode"] = "json"
	authOpts["jwt_response_mode"] = "json"
	authOpts["jwt_host"] = strings.Replace(mockServer.URL, "http://", "", -1)
	authOpts["jwt_port"] = ""
	authOpts["jwt_getuser_uri"] = "/user"
	authOpts["jwt_superuser_uri"] = "/superuser"
	authOpts["jwt_aclcheck_uri"] = "/acl"

	Convey("Given correct options an http backend instance should be returned", t, func() {
		hb, err := NewJWT(authOpts, log.DebugLevel, hashing.NewHasher(authOpts, ""))
		So(err, ShouldBeNil)

		Convey("Given correct password/username, get user should return true", func() {

			authenticated := hb.GetUser(token, "", "")
			So(authenticated, ShouldBeTrue)

		})

		Convey("Given incorrect password/username, get user should return false", func() {

			authenticated := hb.GetUser(wrongToken, "", "")
			So(authenticated, ShouldBeFalse)

		})

		Convey("Given correct username, get superuser should return true", func() {

			authenticated := hb.GetSuperuser(token)
			So(authenticated, ShouldBeTrue)

			Convey("But disabling superusers by removing superuri should now return false", func() {
				authOpts["jwt_superuser_uri"] = ""
				hb, err := NewJWT(authOpts, log.DebugLevel, hashing.NewHasher(authOpts, ""))
				So(err, ShouldBeNil)

				superuser := hb.GetSuperuser(username)
				So(superuser, ShouldBeFalse)
			})

		})

		Convey("Given incorrect username, get superuser should return false", func() {

			authenticated := hb.GetSuperuser(wrongToken)
			So(authenticated, ShouldBeFalse)

		})

		Convey("Given correct topic, username, client id and acc, acl check should return true", func() {

			authenticated := hb.CheckAcl(token, topic, clientID, MOSQ_ACL_READ)
			So(authenticated, ShouldBeTrue)

		})

		Convey("Given an acc that requires more privileges than the user has, check acl should return false", func() {

			authenticated := hb.CheckAcl(token, topic, clientID, MOSQ_ACL_WRITE)
			So(authenticated, ShouldBeFalse)

		})

		Convey("Given a topic not present in acls, check acl should return false", func() {

			authenticated := hb.CheckAcl(token, "fake/topic", clientID, MOSQ_ACL_READ)
			So(authenticated, ShouldBeFalse)

		})

		Convey("Given a clientID that doesn't match, check acl should return false", func() {

			authenticated := hb.CheckAcl(token, topic, "fake_client_id", MOSQ_ACL_READ)
			So(authenticated, ShouldBeFalse)

		})

		hb.Halt()

	})

}

func TestJWTJsonStatusOnlyServer(t *testing.T) {

	topic := "test/topic"
	var acc = int64(1)
	clientID := "test_client"
	token, _ := jwtToken.SignedString([]byte(jwtSecret))
	wrongToken, _ := wrongJwtToken.SignedString([]byte(jwtSecret))

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		var data interface{}
		var params map[string]interface{}

		body, _ := ioutil.ReadAll(r.Body)
		defer r.Body.Close()

		err := json.Unmarshal(body, &data)

		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
		}

		gToken := r.Header.Get("Authorization")
		gToken = strings.TrimPrefix(gToken, "Bearer ")

		if token != gToken {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		switch r.URL.Path {
		case "/user", "/superuser":
			w.WriteHeader(http.StatusOK)
		case "/acl":
			params = data.(map[string]interface{})
			paramsAcc := int64(params["acc"].(float64))
			if params["topic"].(string) == topic && params["clientid"].(string) == clientID && paramsAcc <= acc {
				w.WriteHeader(http.StatusOK)
				break
			}
			w.WriteHeader(http.StatusNotFound)
		}

	}))

	defer mockServer.Close()

	authOpts := make(map[string]string)
	authOpts["jwt_mode"] = "remote"
	authOpts["jwt_params_mode"] = "json"
	authOpts["jwt_response_mode"] = "status"
	authOpts["jwt_host"] = strings.Replace(mockServer.URL, "http://", "", -1)
	authOpts["jwt_port"] = ""
	authOpts["jwt_getuser_uri"] = "/user"
	authOpts["jwt_superuser_uri"] = "/superuser"
	authOpts["jwt_aclcheck_uri"] = "/acl"

	Convey("Given correct options an http backend instance should be returned", t, func() {
		hb, err := NewJWT(authOpts, log.DebugLevel, hashing.NewHasher(authOpts, ""))
		So(err, ShouldBeNil)

		Convey("Given correct password/username, get user should return true", func() {

			authenticated := hb.GetUser(token, "", "")
			So(authenticated, ShouldBeTrue)

		})

		Convey("Given incorrect password/username, get user should return false", func() {

			authenticated := hb.GetUser(wrongToken, "", "")
			So(authenticated, ShouldBeFalse)

		})

		Convey("Given correct username, get superuser should return true", func() {

			authenticated := hb.GetSuperuser(token)
			So(authenticated, ShouldBeTrue)

			Convey("But disabling superusers by removing superuri should now return false", func() {
				authOpts["jwt_superuser_uri"] = ""
				hb, err := NewJWT(authOpts, log.DebugLevel, hashing.NewHasher(authOpts, ""))
				So(err, ShouldBeNil)

				superuser := hb.GetSuperuser(username)
				So(superuser, ShouldBeFalse)
			})

		})

		Convey("Given incorrect username, get superuser should return false", func() {

			authenticated := hb.GetSuperuser(wrongToken)
			So(authenticated, ShouldBeFalse)

		})

		Convey("Given correct topic, username, client id and acc, acl check should return true", func() {

			authenticated := hb.CheckAcl(token, topic, clientID, MOSQ_ACL_READ)
			So(authenticated, ShouldBeTrue)

		})

		Convey("Given an acc that requires more privileges than the user has, check acl should return false", func() {

			authenticated := hb.CheckAcl(token, topic, clientID, MOSQ_ACL_WRITE)
			So(authenticated, ShouldBeFalse)

		})

		Convey("Given a topic not present in acls, check acl should return false", func() {

			authenticated := hb.CheckAcl(token, "fake/topic", clientID, MOSQ_ACL_READ)
			So(authenticated, ShouldBeFalse)

		})

		Convey("Given a clientID that doesn't match, check acl should return false", func() {

			authenticated := hb.CheckAcl(token, topic, "fake_client_id", MOSQ_ACL_READ)
			So(authenticated, ShouldBeFalse)

		})

		hb.Halt()

	})

}

func TestJWTJsonTextResponseServer(t *testing.T) {

	topic := "test/topic"
	var acc = int64(1)
	clientID := "test_client"
	token, _ := jwtToken.SignedString([]byte(jwtSecret))
	wrongToken, _ := wrongJwtToken.SignedString([]byte(jwtSecret))

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		var data interface{}
		var params map[string]interface{}

		body, _ := ioutil.ReadAll(r.Body)
		defer r.Body.Close()

		err := json.Unmarshal(body, &data)

		w.WriteHeader(http.StatusOK)

		if err != nil {
			w.Write([]byte(err.Error()))
		}

		gToken := r.Header.Get("Authorization")
		gToken = strings.TrimPrefix(gToken, "Bearer ")

		if token != gToken {
			w.Write([]byte("Wrong credentials."))
			return
		}

		switch r.URL.Path {
		case "/user", "/superuser":
			w.Write([]byte("ok"))
		case "/acl":
			params = data.(map[string]interface{})
			paramsAcc := int64(params["acc"].(float64))
			if params["topic"].(string) == topic && params["clientid"].(string) == clientID && paramsAcc <= acc {
				w.Write([]byte("ok"))
				break
			}
			w.Write([]byte("Acl check failed."))
		}

	}))

	defer mockServer.Close()

	authOpts := make(map[string]string)
	authOpts["jwt_mode"] = "remote"
	authOpts["jwt_params_mode"] = "json"
	authOpts["jwt_response_mode"] = "text"
	authOpts["jwt_host"] = strings.Replace(mockServer.URL, "http://", "", -1)
	authOpts["jwt_port"] = ""
	authOpts["jwt_getuser_uri"] = "/user"
	authOpts["jwt_superuser_uri"] = "/superuser"
	authOpts["jwt_aclcheck_uri"] = "/acl"

	Convey("Given correct options an http backend instance should be returned", t, func() {
		hb, err := NewJWT(authOpts, log.DebugLevel, hashing.NewHasher(authOpts, ""))
		So(err, ShouldBeNil)

		Convey("Given correct password/username, get user should return true", func() {

			authenticated := hb.GetUser(token, "", "")
			So(authenticated, ShouldBeTrue)

		})

		Convey("Given incorrect password/username, get user should return false", func() {

			authenticated := hb.GetUser(wrongToken, "", "")
			So(authenticated, ShouldBeFalse)

		})

		Convey("Given correct username, get superuser should return true", func() {

			authenticated := hb.GetSuperuser(token)
			So(authenticated, ShouldBeTrue)

			Convey("But disabling superusers by removing superuri should now return false", func() {
				authOpts["jwt_superuser_uri"] = ""
				hb, err := NewJWT(authOpts, log.DebugLevel, hashing.NewHasher(authOpts, ""))
				So(err, ShouldBeNil)

				superuser := hb.GetSuperuser(username)
				So(superuser, ShouldBeFalse)
			})

		})

		Convey("Given incorrect username, get superuser should return false", func() {

			authenticated := hb.GetSuperuser(wrongToken)
			So(authenticated, ShouldBeFalse)

		})

		Convey("Given correct topic, username, client id and acc, acl check should return true", func() {

			authenticated := hb.CheckAcl(token, topic, clientID, MOSQ_ACL_READ)
			So(authenticated, ShouldBeTrue)

		})

		Convey("Given an acc that requires more privileges than the user has, check acl should return false", func() {

			authenticated := hb.CheckAcl(token, topic, clientID, MOSQ_ACL_WRITE)
			So(authenticated, ShouldBeFalse)

		})

		Convey("Given a topic not present in acls, check acl should return false", func() {

			authenticated := hb.CheckAcl(token, "fake/topic", clientID, MOSQ_ACL_READ)
			So(authenticated, ShouldBeFalse)

		})

		Convey("Given a clientID that doesn't match, check acl should return false", func() {

			authenticated := hb.CheckAcl(token, topic, "fake_client_id", MOSQ_ACL_READ)
			So(authenticated, ShouldBeFalse)

		})

		hb.Halt()

	})

}

func TestJWTFormJsonResponseServer(t *testing.T) {

	topic := "test/topic"
	var acc = int64(1)
	clientID := "test_client"
	token, _ := jwtToken.SignedString([]byte(jwtSecret))
	wrongToken, _ := wrongJwtToken.SignedString([]byte(jwtSecret))

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		httpResponse := &HTTPResponse{
			Ok:    true,
			Error: "",
		}

		err := r.ParseForm()
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		var params = r.Form
		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")

		gToken := r.Header.Get("Authorization")
		gToken = strings.TrimPrefix(gToken, "Bearer ")

		if token != gToken {
			httpResponse.Ok = false
			httpResponse.Error = "Wrong credentials."
		} else {
			switch r.URL.Path {
			case "/user", "/superuser":
				httpResponse.Ok = true
				httpResponse.Error = ""
			case "/acl":
				paramsAcc, _ := strconv.ParseInt(params["acc"][0], 10, 64)
				if params["topic"][0] == topic && params["clientid"][0] == clientID && paramsAcc <= acc {
					httpResponse.Ok = true
					httpResponse.Error = ""
					break
				}
				httpResponse.Ok = false
				httpResponse.Error = "Acl check failed."
			}
		}

		jsonResponse, err := json.Marshal(httpResponse)
		if err != nil {
			w.Write([]byte("error"))
		}

		w.Write(jsonResponse)

	}))

	defer mockServer.Close()

	authOpts := make(map[string]string)
	authOpts["jwt_mode"] = "remote"
	authOpts["jwt_params_mode"] = "form"
	authOpts["jwt_response_mode"] = "json"
	authOpts["jwt_host"] = strings.Replace(mockServer.URL, "http://", "", -1)
	authOpts["jwt_port"] = ""
	authOpts["jwt_getuser_uri"] = "/user"
	authOpts["jwt_superuser_uri"] = "/superuser"
	authOpts["jwt_aclcheck_uri"] = "/acl"

	Convey("Given correct options an http backend instance should be returned", t, func() {
		hb, err := NewJWT(authOpts, log.DebugLevel, hashing.NewHasher(authOpts, ""))
		So(err, ShouldBeNil)

		Convey("Given correct password/username, get user should return true", func() {

			authenticated := hb.GetUser(token, "", "")
			So(authenticated, ShouldBeTrue)

		})

		Convey("Given incorrect password/username, get user should return false", func() {

			authenticated := hb.GetUser(wrongToken, "", "")
			So(authenticated, ShouldBeFalse)

		})

		Convey("Given correct username, get superuser should return true", func() {

			authenticated := hb.GetSuperuser(token)
			So(authenticated, ShouldBeTrue)

			Convey("But disabling superusers by removing superuri should now return false", func() {
				authOpts["jwt_superuser_uri"] = ""
				hb, err := NewJWT(authOpts, log.DebugLevel, hashing.NewHasher(authOpts, ""))
				So(err, ShouldBeNil)

				superuser := hb.GetSuperuser(username)
				So(superuser, ShouldBeFalse)
			})

		})

		Convey("Given incorrect username, get superuser should return false", func() {

			authenticated := hb.GetSuperuser(wrongToken)
			So(authenticated, ShouldBeFalse)

		})

		Convey("Given correct topic, username, client id and acc, acl check should return true", func() {

			authenticated := hb.CheckAcl(token, topic, clientID, MOSQ_ACL_READ)
			So(authenticated, ShouldBeTrue)

		})

		Convey("Given an acc that requires more privileges than the user has, check acl should return false", func() {

			authenticated := hb.CheckAcl(token, topic, clientID, MOSQ_ACL_WRITE)
			So(authenticated, ShouldBeFalse)

		})

		Convey("Given a topic not present in acls, check acl should return false", func() {

			authenticated := hb.CheckAcl(token, "fake/topic", clientID, MOSQ_ACL_READ)
			So(authenticated, ShouldBeFalse)

		})

		Convey("Given a clientID that doesn't match, check acl should return false", func() {

			authenticated := hb.CheckAcl(token, topic, "fake_client_id", MOSQ_ACL_READ)
			So(authenticated, ShouldBeFalse)

		})

		hb.Halt()

	})

}

func TestJWTFormStatusOnlyServer(t *testing.T) {

	topic := "test/topic"
	var acc = int64(1)
	clientID := "test_client"
	token, _ := jwtToken.SignedString([]byte(jwtSecret))
	wrongToken, _ := wrongJwtToken.SignedString([]byte(jwtSecret))

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		err := r.ParseForm()
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		var params = r.Form

		gToken := r.Header.Get("Authorization")
		gToken = strings.TrimPrefix(gToken, "Bearer ")

		if token != gToken {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		switch r.URL.Path {
		case "/user", "/superuser":
			w.WriteHeader(http.StatusOK)
		case "/acl":
			paramsAcc, _ := strconv.ParseInt(params["acc"][0], 10, 64)
			if params["topic"][0] == topic && params["clientid"][0] == clientID && paramsAcc <= acc {
				w.WriteHeader(http.StatusOK)
				break
			}
			w.WriteHeader(http.StatusNotFound)
		}

	}))

	defer mockServer.Close()

	authOpts := make(map[string]string)
	authOpts["jwt_mode"] = "remote"
	authOpts["jwt_params_mode"] = "form"
	authOpts["jwt_response_mode"] = "status"
	authOpts["jwt_host"] = strings.Replace(mockServer.URL, "http://", "", -1)
	authOpts["jwt_port"] = ""
	authOpts["jwt_getuser_uri"] = "/user"
	authOpts["jwt_superuser_uri"] = "/superuser"
	authOpts["jwt_aclcheck_uri"] = "/acl"

	Convey("Given correct options an http backend instance should be returned", t, func() {
		hb, err := NewJWT(authOpts, log.DebugLevel, hashing.NewHasher(authOpts, ""))
		So(err, ShouldBeNil)

		Convey("Given correct password/username, get user should return true", func() {

			authenticated := hb.GetUser(token, "", "")
			So(authenticated, ShouldBeTrue)

		})

		Convey("Given incorrect password/username, get user should return false", func() {

			authenticated := hb.GetUser(wrongToken, "", "")
			So(authenticated, ShouldBeFalse)

		})

		Convey("Given correct username, get superuser should return true", func() {

			authenticated := hb.GetSuperuser(token)
			So(authenticated, ShouldBeTrue)

			Convey("But disabling superusers by removing superuri should now return false", func() {
				authOpts["jwt_superuser_uri"] = ""
				hb, err := NewJWT(authOpts, log.DebugLevel, hashing.NewHasher(authOpts, ""))
				So(err, ShouldBeNil)

				superuser := hb.GetSuperuser(username)
				So(superuser, ShouldBeFalse)
			})

		})

		Convey("Given incorrect username, get superuser should return false", func() {

			authenticated := hb.GetSuperuser(wrongToken)
			So(authenticated, ShouldBeFalse)

		})

		Convey("Given correct topic, username, client id and acc, acl check should return true", func() {

			authenticated := hb.CheckAcl(token, topic, clientID, MOSQ_ACL_READ)
			So(authenticated, ShouldBeTrue)

		})

		Convey("Given an acc that requires more privileges than the user has, check acl should return false", func() {

			authenticated := hb.CheckAcl(token, topic, clientID, MOSQ_ACL_WRITE)
			So(authenticated, ShouldBeFalse)

		})

		Convey("Given a topic not present in acls, check acl should return false", func() {

			authenticated := hb.CheckAcl(token, "fake/topic", clientID, MOSQ_ACL_READ)
			So(authenticated, ShouldBeFalse)

		})

		Convey("Given a clientID that doesn't match, check acl should return false", func() {

			authenticated := hb.CheckAcl(token, topic, "fake_client_id", MOSQ_ACL_READ)
			So(authenticated, ShouldBeFalse)

		})

		hb.Halt()

	})

}

func TestJWTFormTextResponseServer(t *testing.T) {

	topic := "test/topic"
	var acc = int64(1)
	clientID := "test_client"
	token, _ := jwtToken.SignedString([]byte(jwtSecret))
	wrongToken, _ := wrongJwtToken.SignedString([]byte(jwtSecret))

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		w.WriteHeader(http.StatusOK)

		err := r.ParseForm()
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		var params = r.Form

		gToken := r.Header.Get("Authorization")
		gToken = strings.TrimPrefix(gToken, "Bearer ")

		if token != gToken {
			w.Write([]byte("Wrong credentials."))
			return
		}

		switch r.URL.Path {
		case "/user", "/superuser":
			w.Write([]byte("ok"))
		case "/acl":
			paramsAcc, _ := strconv.ParseInt(params["acc"][0], 10, 64)
			if params["topic"][0] == topic && params["clientid"][0] == clientID && paramsAcc <= acc {
				w.Write([]byte("ok"))
				break
			}
			w.Write([]byte("Acl check failed."))
		}

	}))

	defer mockServer.Close()

	authOpts := make(map[string]string)
	authOpts["jwt_mode"] = "remote"
	authOpts["jwt_params_mode"] = "form"
	authOpts["jwt_response_mode"] = "text"
	authOpts["jwt_host"] = strings.Replace(mockServer.URL, "http://", "", -1)
	authOpts["jwt_port"] = ""
	authOpts["jwt_getuser_uri"] = "/user"
	authOpts["jwt_superuser_uri"] = "/superuser"
	authOpts["jwt_aclcheck_uri"] = "/acl"

	Convey("Given correct options an http backend instance should be returned", t, func() {
		hb, err := NewJWT(authOpts, log.DebugLevel, hashing.NewHasher(authOpts, ""))
		So(err, ShouldBeNil)

		Convey("Given correct password/username, get user should return true", func() {

			authenticated := hb.GetUser(token, "", "")
			So(authenticated, ShouldBeTrue)

		})

		Convey("Given incorrect password/username, get user should return false", func() {

			authenticated := hb.GetUser(wrongToken, "", "")
			So(authenticated, ShouldBeFalse)

		})

		Convey("Given correct username, get superuser should return true", func() {

			authenticated := hb.GetSuperuser(token)
			So(authenticated, ShouldBeTrue)

			Convey("But disabling superusers by removing superuri should now return false", func() {
				authOpts["jwt_superuser_uri"] = ""
				hb, err := NewJWT(authOpts, log.DebugLevel, hashing.NewHasher(authOpts, ""))
				So(err, ShouldBeNil)

				superuser := hb.GetSuperuser(username)
				So(superuser, ShouldBeFalse)
			})

		})

		Convey("Given incorrect username, get superuser should return false", func() {

			authenticated := hb.GetSuperuser(wrongToken)
			So(authenticated, ShouldBeFalse)

		})

		Convey("Given correct topic, username, client id and acc, acl check should return true", func() {

			authenticated := hb.CheckAcl(token, topic, clientID, MOSQ_ACL_READ)
			So(authenticated, ShouldBeTrue)

		})

		Convey("Given an acc that requires more privileges than the user has, check acl should return false", func() {

			authenticated := hb.CheckAcl(token, topic, clientID, MOSQ_ACL_WRITE)
			So(authenticated, ShouldBeFalse)

		})

		Convey("Given a topic not present in acls, check acl should return false", func() {

			authenticated := hb.CheckAcl(token, "fake/topic", clientID, MOSQ_ACL_READ)
			So(authenticated, ShouldBeFalse)

		})

		Convey("Given a clientID that doesn't match, check acl should return false", func() {

			authenticated := hb.CheckAcl(token, topic, "fake_client_id", MOSQ_ACL_READ)
			So(authenticated, ShouldBeFalse)

		})

		hb.Halt()

	})

}
