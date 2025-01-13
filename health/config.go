// Copyright 2025 The go-MemeCore Authors
// This file is part of go-MemeCore.
//
// The go-MemeCore library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-MemeCore library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-MemeCore library. If not, see <http://www.gnu.org/licenses/>.

package health

// Config contains the configuration for the health check.
type Config struct {
	Enabled bool   `toml:",omitempty"`
	Path    string `toml:",omitempty"`
}

// DefaultConfig is the default config for health check used in go-MemeCore.
var DefaultConfig = Config{
	Enabled: false,
	Path:    "/health",
}
