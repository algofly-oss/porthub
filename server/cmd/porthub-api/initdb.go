package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// initDB is the first start of the embedded MongoDB: it creates the root
// user from MONGO_INITDB_ROOT_USERNAME/PASSWORD, restoring
// /data/restore/mongo.archive.gz first when present (without its admin
// database, so only the new credentials apply). Runs once.
func initDB() error {
	const dbpath, archive, uri = "/data/mongo", "/data/restore/mongo.archive.gz", "mongodb://127.0.0.1:47017"
	user, password := os.Getenv("MONGO_INITDB_ROOT_USERNAME"), os.Getenv("MONGO_INITDB_ROOT_PASSWORD")
	if user == "" || password == "" {
		return fmt.Errorf("MONGO_INITDB_ROOT_USERNAME and MONGO_INITDB_ROOT_PASSWORD are required")
	}
	mongod := exec.Command("mongod", "--bind_ip", "127.0.0.1", "--port", "47017", "--dbpath", dbpath, "--quiet")
	if err := mongod.Start(); err != nil {
		return err
	}
	ctx := context.Background()
	client, err := mongo.Connect(options.Client().ApplyURI(uri).SetServerSelectionTimeout(2 * time.Second))
	if err != nil {
		return err
	}
	defer func() {
		_ = client.Database("admin").RunCommand(ctx, bson.D{{Key: "shutdown", Value: 1}}).Err()
		_ = mongod.Wait()
	}()
	ready := false
	for range 60 {
		if client.Ping(ctx, nil) == nil {
			ready = true
			break
		}
		time.Sleep(time.Second)
	}
	if !ready {
		return fmt.Errorf("mongod did not start")
	}
	if _, err := os.Stat(archive); err == nil {
		log.Printf("restoring %s", archive)
		restored := false
		for range 3 {
			out, err := exec.Command("mongorestore", "--uri", uri, "--gzip", "--archive="+archive, "--nsExclude=admin.*", "--drop").CombinedOutput()
			lines := strings.Split(strings.TrimSpace(string(out)), "\n")
			if err == nil {
				log.Print(lines[len(lines)-1])
				restored = true
				break
			}
			log.Printf("restore attempt failed:\n%s", strings.Join(lines[max(0, len(lines)-8):], "\n"))
			time.Sleep(3 * time.Second)
		}
		if !restored {
			return fmt.Errorf("could not restore the database archive")
		}
	}
	var info struct {
		Users []bson.M `bson:"users"`
	}
	admin := client.Database("admin")
	if err := admin.RunCommand(ctx, bson.D{{Key: "usersInfo", Value: user}}).Decode(&info); err != nil {
		return err
	}
	if len(info.Users) > 0 {
		err = admin.RunCommand(ctx, bson.D{{Key: "updateUser", Value: user}, {Key: "pwd", Value: password}}).Err()
	} else {
		err = admin.RunCommand(ctx, bson.D{{Key: "createUser", Value: user}, {Key: "pwd", Value: password}, {Key: "roles", Value: bson.A{"root"}}}).Err()
	}
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dbpath, ".porthub-initialized"), nil, 0o644); err != nil {
		return err
	}
	log.Print("database initialized")
	return nil
}
