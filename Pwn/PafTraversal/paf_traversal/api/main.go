package main

func main() {
	router := SetupRouter()

	err := router.Run(":8000")
	if err != nil {
		return
	}
}
