package bundleTestSupport

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"

	"github.com/hexa-org/policy-mapper/providers/openpolicyagent"
	"github.com/hexa-org/policy-opa/cmd/hexaAuthZen/config"
	"github.com/hexa-org/policy-opa/pkg/compressionsupport"
	"github.com/stretchr/testify/assert"
)

var dataString = `
{
  "policies": [
    {
      "meta": {
        "policyId": "GetUsers",
        "version": "0.6",
        "description": "Get information (e.g. email, picture) associated with a user"
      },
      "subject": {
        "members": ["anyAuthenticated"]
      },
      "actions": [
        {
          "actionUri": "can_read_user"
        }
      ],
      "object": {
        "resource_id": "todo"
      }
    },
    {
      "meta": {
        "policyId": "GetTodos",
        "version": "0.6",

        "description": "Get the list of todos. Always returns true for every user??"
      },
      "subject": {
        "members": ["anyAuthenticated"]
      },
      "actions": [
        {
          "actionUri": "can_read_todos"
        }
      ],
      "object": {
        "resource_id": "todo"
      }
    },
    {
      "meta": {
        "version": "0.6",
        "description": "Create a new Todo",
        "policyId": "PostTodo"
      },
      "subject": {
        "members": ["role:admin","role:editor"]
      },
      "actions": [
        {
          "actionUri": "can_create_todo"
        }
      ],
      "object": {
        "resource_id": "todo"
      }
    },
    {
      "meta": {
        "version": "0.6",
        "description": "Edit(complete) a todo.",
        "policyId": "PutTodo"
      },
      "subject": {
        "members": ["anyAuthenticated"]
      },
      "actions": [
        {
          "actionUri": "can_update_todo"
        }
      ],
      "condition": {
        "rule": "subject.roles co evil_genius or ( subject.roles co editor and resource.ownerID eq subject.claims.id )",
        "action": "allow"
      },
      "object": {
        "resource_id": "todo"
      }
    },
    {
      "meta": {
        "version": "0.6",
        "description": "Delete a todo if admin or owner of todo",
        "policyId": "DeleteTodo"
      },
      "subject": {
        "members": ["anyAuthenticated"]
      },
      "actions": [
        {
          "actionUri": "can_delete_todo"
        }
      ],
      "condition": {
        "rule": "subject.roles co admin or ( subject.roles co editor and resource.ownerID eq subject.claims.id )",
        "action": "allow"
      },
      "object": {
        "resource_id": "todo"
      }
    }
  ]
}`

func Cleanup(path string) {
	_ = os.RemoveAll(path)
}

// GetTestBundle returns tar/gziped bundle from the specified path
func GetTestBundle(path string) ([]byte, error) {
	tar, _ := compressionsupport.TarFromPath(path)

	var output []byte
	writer := bytes.NewBuffer(output)
	err := compressionsupport.Gzip(writer, tar)

	return writer.Bytes(), err
}

// GetTestBundlePath returns a path relative to the package
func GetTestBundlePath(bundle string) string {
	_, file, _, _ := runtime.Caller(0)

	return filepath.Join(path.Dir(file), bundle)
}

func InitTestEmptyBundleDir(t *testing.T) string {
	tempDir, err := os.MkdirTemp("", "policy-opa-empty-*")
	assert.NoError(t, err, "No error creating tempdir")

	return tempDir
}

func InitTestBundlesDir(data []byte) string {
	tempDir, _ := os.MkdirTemp("", "policy-opa-test-*")

	var databytes []byte
	if data == nil {
		databytes = []byte(dataString)
	} else {
		databytes = data
	}
	bundleBuf, _ := openpolicyagent.MakeHexaBundle(databytes)

	gzip, _ := compressionsupport.UnGzip(bytes.NewReader(bundleBuf.Bytes()))

	_ = compressionsupport.UnTarToPath(bytes.NewReader(gzip), tempDir)

	return tempDir
}

func PrepareBundleUploadRequest(path string) (*http.Request, error) {
	testBundle, _ := GetTestBundle(path)

	buf := new(bytes.Buffer)
	writer := multipart.NewWriter(buf)
	formFile, _ := writer.CreateFormFile("bundle", "bundle.tar.gz")
	_, _ = formFile.Write(testBundle)
	_ = writer.Close()

	req, err := http.NewRequest("POST", config.EndpointOpaBundles, buf)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", writer.FormDataContentType())
	req.Header.Add("Content-Length", strconv.Itoa(buf.Len()))

	return req, err

}
