// Copyright (C) 2017 Space Monkey, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package httpsig

type MemoryKeyStore struct {
	keys map[string]interface{}
	keyAlgorithms map[string]Algorithm
}

func NewMemoryKeyStore() *MemoryKeyStore {
	return &MemoryKeyStore{
		keys: make(map[string]interface{}),
		keyAlgorithms: make(map[string]Algorithm),
	}
}

func (m *MemoryKeyStore) GetKey(id string) interface{} {
	return m.keys[id]
}

func (m *MemoryKeyStore) SetKey(id string, key interface{}) {
	m.keys[id] = key
}

func (m *MemoryKeyStore) SetKeyAlgorithm(id string, algorithm Algorithm) {
	m.keyAlgorithms[id] = algorithm
}

func (m *MemoryKeyStore) GetKeyAlgorithm(id string) Algorithm {
	return m.keyAlgorithms[id]
}
