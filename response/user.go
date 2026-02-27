package response

type UserAppRow struct {
	ID         uint
	Email      string
	FirstName  string
	LastName   string
	RoleName   string
	IsVerified bool
	IsActive   bool
}
