package storage

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// R2StorageService implementa StorageService usando Cloudflare R2 / AWS S3.
type R2StorageService struct {
	client    *s3.Client
	bucket    string
	publicURL string
}

// NewR2StorageService crea un nuevo cliente conectado a Cloudflare R2 u otro bucket S3 compatible.
func NewR2StorageService(accountID, accessKeyID, secretAccessKey, bucket, publicURL string) (*R2StorageService, error) {
	if accountID == "" || accessKeyID == "" || secretAccessKey == "" || bucket == "" {
		return nil, fmt.Errorf("credenciales incompletas para Cloudflare R2")
	}

	r2Endpoint := fmt.Sprintf("https://%s.r2.cloudflarestorage.com", accountID)

	cfg, err := config.LoadDefaultConfig(context.Background(),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(accessKeyID, secretAccessKey, "")),
		config.WithRegion("auto"),
	)
	if err != nil {
		return nil, fmt.Errorf("error inicializando configuración de S3/R2: %w", err)
	}

	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(r2Endpoint)
		o.UsePathStyle = true
	})

	trimmedPublic := strings.TrimRight(publicURL, "/")
	if trimmedPublic == "" {
		trimmedPublic = fmt.Sprintf("https://%s.r2.cloudflarestorage.com/%s", accountID, bucket)
	}

	return &R2StorageService{
		client:    client,
		bucket:    bucket,
		publicURL: trimmedPublic,
	}, nil
}

// Upload valida el archivo, verifica sus magic bytes y lo sube al bucket de R2.
func (s *R2StorageService) Upload(ctx context.Context, r io.Reader, originalFilename string, folder string) (string, error) {
	upload, err := ValidateAndPrepareUpload(r, originalFilename, folder)
	if err != nil {
		return "", err
	}

	key := fmt.Sprintf("%s/%s", folder, upload.Filename)

	_, err = s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:       aws.String(s.bucket),
		Key:          aws.String(key),
		Body:         bytes.NewReader(upload.Data),
		ContentType:  aws.String(upload.MIMEType),
		CacheControl: aws.String("public, max-age=31536000, immutable"),
	})
	if err != nil {
		return "", fmt.Errorf("error al subir archivo a Cloudflare R2: %w", err)
	}

	return fmt.Sprintf("%s/%s", s.publicURL, key), nil
}

// Delete elimina un archivo de R2 dado su URL pública.
func (s *R2StorageService) Delete(ctx context.Context, fileURL string) error {
	if !strings.HasPrefix(fileURL, s.publicURL) {
		return nil
	}

	key := strings.TrimPrefix(fileURL, s.publicURL)
	key = strings.TrimPrefix(key, "/")

	if key == "" {
		return nil
	}

	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return fmt.Errorf("error eliminando archivo de Cloudflare R2: %w", err)
	}

	return nil
}
