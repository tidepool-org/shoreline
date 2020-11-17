package keycloak

import "github.com/golang/mock/gomock"

func (m *MockClient) Reset(ctrl *gomock.Controller) {
	m.ctrl = ctrl
	m.recorder = &MockClientMockRecorder{mock: m}
}
