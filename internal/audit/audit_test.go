package audit

import (
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestAuditEvents(t *testing.T) {
	gin.SetMode(gin.TestMode)

	t.Run("Event with nil context does not panic", func(t *testing.T) {
		Event(nil, "test.action", "target=1")
	})

	t.Run("EventResult with nil context does not panic", func(t *testing.T) {
		EventResult(nil, "test.action", "target=1", false, "some error")
	})

	t.Run("Event with populated gin context", func(t *testing.T) {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest("GET", "/test", nil)
		c.Set("request_id", "req-123")
		c.Set("user_email", "admin@example.com")
		c.Set("user_id", uint(42))

		Event(c, "app.create", "app=my-app")
		EventResult(c, "app.delete", "app=my-app", true, "success")
		EventResult(c, "app.delete", "app=my-app", false, "unauthorized")
	})
}
