package backends

import (
	"database/sql"
	"strconv"
	"strings"

	"github.com/iegomez/mosquitto-go-auth/backends/topics"
	"github.com/iegomez/mosquitto-go-auth/hashing"
	"github.com/jmoiron/sqlx"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	_ "github.com/ClickHouse/clickhouse-go"
)

//Clickhouse holds all fields of the postgres db connection.
type Clickhouse struct {
	DB             	*sqlx.DB
	Dsn            	string
	hasher         	hashing.HashComparer
	UserQuery	string
	SuperuserQuery	string
	AclQuery	string
    
	connectTries int
}

func NewClickhouse(authOpts map[string]string, logLevel log.Level, hasher hashing.HashComparer) (Clickhouse, error) {

	log.SetLevel(logLevel)

	//Set defaults for postgres

	chOk := true
	missingOptions := ""

	var ch = Clickhouse{
		Dsn:           "tcp://localhost:9000",
		SuperuserQuery: "",
                AclQuery:       "",
                hasher:         hasher,
                connectTries:   -1,
	}

	if dsn, ok := authOpts["clickhouse_dsn"]; ok {
		ch.Dsn = dsn
	}

	if userQuery, ok := authOpts["clickhouse_userquery"]; ok {
		ch.UserQuery = userQuery
	} else {
		chOk = false
		missingOptions += " clickhouse_userquery"
	}

	if superuserQuery, ok := authOpts["clickhouse_superquery"]; ok {
		ch.SuperuserQuery = superuserQuery
	}

	if aclQuery, ok := authOpts["clickhouse_aclquery"]; ok {
		ch.AclQuery = aclQuery
	}

	//Exit if any mandatory option is missing.
	if !chOk {
		return ch, errors.Errorf("Clickhouse backend error: missing options: %s", missingOptions)
	}

	if tries, ok := authOpts["clickhouse_connect_tries"]; ok {
                connectTries, err := strconv.Atoi(tries)
        
                if err != nil {
                        log.Warnf("invalid clickhouse connect tries options: %s", err)
                } else {
                        ch.connectTries = connectTries
                }
        }

	var err error
	ch.DB, err = OpenDatabase(ch.Dsn, "clickhouse", ch.connectTries)

	if err != nil {
		return ch, errors.Errorf("Clickhouse backend error: couldn't open db: %s", err)
	}

	return ch, nil

}

//GetUser checks that the username exists and the given password hashes to the same password.
func (o Clickhouse) GetUser(username, password, clientid string) (bool, error) {

	var pwHash sql.NullString
	err := o.DB.Get(&pwHash, o.UserQuery, username)

	if err != nil {
		if err == sql.ErrNoRows {
			// avoid leaking the fact that user exists or not though error.
			return false, nil
		}

		log.Debugf("Clickhouse get user error: %s", err)
		return false, err
	}

	if !pwHash.Valid {
		log.Debugf("Clickhouse get user error: user %s not found", username)
		return false, err
	}

	if o.hasher.Compare(password, pwHash.String) {
		return true, nil
	}

	return false, nil

}

//GetSuperuser checks that the username meets the superuser query.
func (o Clickhouse) GetSuperuser(username string) (bool, error) {

	//If there's no superuser query, return false.
	if o.SuperuserQuery == "" {
		return false, nil
	}

	var count sql.NullInt64
	err := o.DB.Get(&count, o.SuperuserQuery, username)

	if err != nil {
		if err == sql.ErrNoRows {
			// avoid leaking the fact that user exists or not though error.
			return false, nil
		}

		log.Debugf("Clickhouse get superuser error: %s", err)
		return false, err
	}

	if !count.Valid {
		log.Debugf("Clickhouse get superuser error: user %s not found", username)
		return false, nil
	}

	if count.Int64 > 0 {
		return true, nil
	}

	return false, nil

}

//CheckAcl gets all acls for the username and tries to match against topic, acc, and username/clientid if needed.
func (o Clickhouse) CheckAcl(username, topic, clientid string, acc int32) (bool, error) {

	//If there's no acl query, assume all privileges for all users.
	if o.AclQuery == "" {
		return true, nil
	}

	var acls []string

	err := o.DB.Select(&acls, o.AclQuery, username, acc)

	if err != nil {
		log.Debugf("PG check acl error: %s", err)
		return false, err
	}

	for _, acl := range acls {
		aclTopic := strings.Replace(acl, "%c", clientid, -1)
		aclTopic = strings.Replace(aclTopic, "%u", username, -1)
		if topics.Match(aclTopic, topic) {
			return true, nil
		}
	}

	return false, nil

}

//GetName returns the backend's name
func (o Clickhouse) GetName() string {
	return "Clickhouse"
}

//Halt closes the connection.
func (o Clickhouse) Halt() {
	if o.DB != nil {
		err := o.DB.Close()
		if err != nil {
			log.Errorf("Clickhouse cleanup error: %s", err)
		}
	}
}
