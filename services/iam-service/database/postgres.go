// database/postgres.go
package database

import (
	"context"
	"log"
	"time"

	"iam-service/config"

	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/olivere/elastic/v7"
	"github.com/redis/go-redis/v9"
)

var (
	DB            *sqlx.DB
	RedisClient   *redis.Client
	ElasticClient *elastic.Client
)

func Connect(cfg *config.Config) error {
	var err error
	DB, err = sqlx.Connect("postgres", cfg.DatabaseURL)
	if err != nil {
		return err
	}

	// Configure connection pool
	DB.SetMaxOpenConns(cfg.DBMaxOpenConns)
	DB.SetMaxIdleConns(cfg.DBMaxIdleConns)
	DB.SetConnMaxLifetime(cfg.DBConnMaxLifetime)

	// Test connection
	if err := DB.Ping(); err != nil {
		return err
	}

	log.Println("Successfully connected to PostgreSQL")
	return nil
}

func InitRedis(cfg *config.Config) error {
	RedisClient = redis.NewClient(&redis.Options{
		Addr:     cfg.RedisURL,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	})

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := RedisClient.Ping(ctx).Err(); err != nil {
		return err
	}

	log.Println("Successfully connected to Redis")
	return nil
}

func InitElasticsearch(cfg *config.Config) error {
	var options []elastic.ClientOptionFunc
	
	options = append(options, elastic.SetURL(cfg.ElasticsearchURL))
	options = append(options, elastic.SetSniff(false))
	options = append(options, elastic.SetHealthcheck(false))
	
	if cfg.ElasticsearchUsername != "" && cfg.ElasticsearchPassword != "" {
		options = append(options, elastic.SetBasicAuth(cfg.ElasticsearchUsername, cfg.ElasticsearchPassword))
	}
	
	client, err := elastic.NewClient(options...)
	if err != nil {
		return err
	}

	ElasticClient = client

	// Check if cluster is running
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	info, code, err := client.Ping(cfg.ElasticsearchURL).Do(ctx)
	if err != nil {
		return err
	}

	log.Printf("Elasticsearch returned with code %d and version %s", code, info.Version.Number)
	return nil
}

func Close() {
	if DB != nil {
		DB.Close()
		log.Println("Database connection closed")
	}
}

func CloseRedis() {
	if RedisClient != nil {
		RedisClient.Close()
		log.Println("Redis connection closed")
	}
}