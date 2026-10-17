package controller

import (
	"fmt"
	"peak-auth/internal/storage"
	"peak-auth/internal/store/model"

	"github.com/gin-gonic/gin"
)

type applicationAccess struct {
	UserID  uint
	IsRoot  bool
	IsOwner bool
}

func getApplicationAccess(c *gin.Context, app model.Application) (applicationAccess, bool) {
	userID, ok := authenticatedUserID(c)
	if !ok {
		return applicationAccess{}, false
	}

	principal, _ := authenticatedPrincipal(c)
	isRoot := principal.IsRoot
	isOwner := app.OwnerID != nil && *app.OwnerID == userID

	return applicationAccess{
		UserID:  userID,
		IsRoot:  isRoot,
		IsOwner: isOwner,
	}, true
}

func uploadApplicationAsset(c *gin.Context, storageService storage.StorageService, field, folder string) (string, bool, error) {
	file, header, err := c.Request.FormFile(field)
	if err != nil {
		return "", false, nil
	}
	defer file.Close()

	if storageService == nil {
		return "", true, fmt.Errorf("storage service unavailable")
	}

	url, err := storageService.Upload(c.Request.Context(), file, header.Filename, folder)
	if err != nil {
		return "", true, err
	}
	return url, true, nil
}
