// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package params

import "github.com/ethereum/go-ethereum/common"

// MainnetBootnodes are the enode URLs of the P2P bootstrap nodes running on
// the main Ethereum network.
var MainnetBootnodes = []string{
	// MemeCore Foundation Go Bootnodes
	"enode://99dd959fd2346450a5d986407a3aea08b3ceda67ffe0eb1991903b0e55de2af9a74d45d15c06289c5c3f33b21538d5e1c99614dc07107b5166ec854c2ad25b77@47.130.61.225:30303",
	"enode://5320c832160f962966822d9e4b2ed2bd14346cbfd0e0228e0371a7c50cad6883c7c9a7a212737cd24890b35d21a3aa5d6a2f4bcdc9e90f5e7ceaa17a11b1ffb2@47.130.70.213:30303",
	"enode://c1a08cdb5b6e97c0bb731979609a6e8941005ee28874115c7ab0e3164fe67f679de17a2279c440bfee957dadd597457e4f0c85d3c35cc6861771bab3f75d10df@47.130.9.126:30303",
	"enode://c77e132751609d24136ee15834f94c2005ccde0b070eeace5462c3e3a06b3686e764a5e378fd96652ea7c9c0b354b9979d437122122369c1911c373b3ed79e5e@54.251.255.43:30303",
	"enode://785019e65a1ddecef2248c81fe2a3b99fd6a98468d7bac2f83e2b2479dca8d52ea39e6a89d539ab35d9592f8a76614b8a09aac64ca43c25fe5bba7af2d4a327f@52.74.133.157:30303",
}

var FormicariumBootnodes = []string{
	"enode://d511b4562fbf87ccf864bf8bf0536632594d5838fc2223cecdb35b30c3b281172c96201a8f9835164b1d8ec1e4d6b7542af917fab7aca891654dae50ce515bc0@18.139.212.120:30303",
	"enode://9b5ae242c202d74db9ba8406d2e225f97bb79487eedba576f20fcf8d770488d6e5d0110b45bcaf01b107d4a429b6cfcb7dea4e07f8dbc9816e8409b0b147036e@54.254.95.106:30303",
	"enode://1e2a44da7a379de161649f227c31025949363d6055c0372a52c8c37208e9aa26eb6bbea92113bf7d62d6d8e425dc5e3a1ba0dd473bc6f38c41b7c8ed4703656b@18.136.3.170:30303",
	"enode://7baf26de1efd7820bced95c89adc68e0aa4ac663f4c4f2d1a79aea253ce39663f1c330b530759acf134fd85933df2cc278e2de8b926ab6f170925b68cb31934c@18.141.252.100:30303",
}

var InsectariumBootnodes = []string{
	"enode://86703c20f0272c99fd8d06089fbdbccf512c97b4fc2d1f0dcbd64ae29638e2a5b196e7940fd090c5b4297529463e1852fd5e94a62aad929025522b6bdec5e811@54.254.15.125:30303",
	"enode://c68e83093bdba08f9682aa3e9c8ef9a749c9d3c07a1cfe7c6ebf9f5d8f311228a24bb1ae1dbbbc4cbc6630958faf57d2c8978615f31760270ebeaefb5ca5c6ce@52.76.153.215:30303",
	"enode://50bfe3c69cffcc360eed7b84802e1888bf4ed4151c3b039513370ee5057c9477714c4aad79e258544f79692146f66ef8aa2b51501d43ea456e3241669e6a2d54@18.139.33.64:30303",
	"enode://da655ba625d17965bc47759f84f3b1bbcc771d516307f647503f183e6cbbb9b799fb85fe2f70e4c2b07a3161e1a4badda2b29f4aadeee27715046891e1971fbc@13.214.74.128:30303",
}

const dnsPrefix = "enrtree://AKA3AM6LPBYEUDMVNU3BSVQJ5AD45Y7YPOHJLEF6W26QOE4VTUDPE@"

// KnownDNSNetwork returns the address of a public DNS-based node list for the given
// genesis hash and protocol. See https://github.com/ethereum/discv4-dns-lists for more
// information.
func KnownDNSNetwork(genesis common.Hash, protocol string) string {
	var net string
	switch genesis {
	case MainnetGenesisHash:
		net = "mainnet"
	case FormicariumGenesisHash:
		net = "formicarium"
	case InsectariumGenesisHash:
		net = "insectarium"
	default:
		return ""
	}
	return dnsPrefix + protocol + "." + net + ".ethdisco.net"
}
