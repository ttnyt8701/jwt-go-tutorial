package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
)

var JWT_SECRET = []byte(os.Getenv("JWT_SECRET"))

func main() {
	// ルーター設定
	r := mux.NewRouter()

	r.HandleFunc("/register", Register).Methods("POST")
	r.HandleFunc("/login", AuthMiddleware(Login)).Methods("GET")

	http.Handle("/", r)
	fmt.Println("Server is running on port 3001")
	log.Fatal(http.ListenAndServe(":3001", nil))
}

type User struct {
	Username string `json:"username"`
	Email    string `json:"email"`
}

// RegisterEndpoint handles user registration
func Register(w http.ResponseWriter, r *http.Request) {
	// ボディからレスを受け取り、インスタンス化
	var user User
	_ = json.NewDecoder(r.Body).Decode(&user)

	// username,emailを含めたJWTを生成
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": user.Username,
		"email":    user.Email,
	})

	// JWT_SECRETを使って署名
	tokenString, _ := token.SignedString(JWT_SECRET)

	// レスポンスを返す
	userResponse := map[string]string{
		"username": user.Username,
		"email":    user.Email,
		"token":    tokenString,
	}

	json.NewEncoder(w).Encode(userResponse)
}

func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// ヘッダーからトークンを取得
		tokenString := r.Header.Get("token")

		// トークンがない場合はエラー
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])

			}
			return JWT_SECRET, nil
		})

		// トークンが無効な場合はエラー
		if err != nil {
			http.Error(w, "Invalid token🥺", http.StatusUnauthorized)
			return
		}

		// トークンが有効な場合は次のハンドラーを実行
		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			fmt.Println(claims)
			next.ServeHTTP(w, r)
		} else {
			http.Error(w, "Invalid token😤", http.StatusUnauthorized)
		}
	}
}

func Login(w http.ResponseWriter, r *http.Request) {
	response := map[string]string{
		"msg": "Login successful",
	}
	json.NewEncoder(w).Encode(response)
}