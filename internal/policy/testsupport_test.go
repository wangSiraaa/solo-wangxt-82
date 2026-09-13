package policy

import "os"

func readFileForTest(path string) ([]byte, error) {
	return os.ReadFile(path)
}
