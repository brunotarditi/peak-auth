package authcontext

import "github.com/gin-gonic/gin"

const principalKey = "auth_principal"

type Principal struct {
	UserID          uint
	Email           string
	Name            string
	Roles           []string
	IsAuthenticated bool
	IsRoot          bool
	IsPlatformAdmin bool
}

func Set(c *gin.Context, principal Principal) {
	c.Set(principalKey, principal)
}

func Get(c *gin.Context) (Principal, bool) {
	value, exists := c.Get(principalKey)
	if !exists {
		return Principal{}, false
	}
	principal, ok := value.(Principal)
	return principal, ok && principal.IsAuthenticated && principal.UserID > 0
}

func UpdateScope(c *gin.Context, isRoot, isPlatformAdmin bool) {
	principal, ok := Get(c)
	if !ok {
		return
	}
	principal.IsRoot = isRoot
	principal.IsPlatformAdmin = isPlatformAdmin
	Set(c, principal)
}
