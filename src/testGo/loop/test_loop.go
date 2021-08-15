package main

import "fmt"

func TestForLoop() {
	sum := 0
	for i := 1; i < 5; i++ {
		sum += i
	}
	fmt.Println(sum) // 10 (1+2+3+4)
}

func TestWhile() {
	sum := 0
	n := 0
	for n < 5 {
		sum += n
		n += 1
	}
	fmt.Println(sum) // 10 (1+2+3+4)
}

func TestInfiniteloop() {
	sum := 0
	for {
		sum++	
		if sum == 100 {
			break
		}	
	}
	fmt.Println(sum)
}

func TestRangeloop() {	
	strings := []string{"hello", "world"}
	for index, str := range strings {
		fmt.Println(index, str)
	}
}

func TestExitloop() {
	sum := 0
	for {
		sum++		
		if sum%2 != 0 {
			continue
		}
		if sum >= 10 {
			break
		}
		fmt.Println(sum)
	}
	fmt.Println(sum)
}

func main() {
	TestForLoop()
	TestWhile()
	TestInfiniteloop()
	TestRangeloop()
	TestExitloop()
}