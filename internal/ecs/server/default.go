package server

/*
 * AWS SSO CLI
 * Copyright (c) 2021-2023 Aaron Turner  <synfinatic at gmail dot com>
 *
 * This program is free software: you can redistribute it
 * and/or modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or with the authors permission any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

import (
	"net/http"

	"github.com/synfinatic/aws-sso-cli/internal/ecs"
)

type DefaultHandler struct {
	ecs *EcsServer
}

func (p DefaultHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		p.Get(w, r)
	case http.MethodPut:
		p.Put(w, r)
	case http.MethodDelete:
		p.Delete(w, r)
	default:
		log.Errorf("Invalid request: %s", r.URL.String())
		Invalid(w)
	}
}

func (p DefaultHandler) Get(w http.ResponseWriter, r *http.Request) {
	log.Debugf("fetching default creds")
	WriteCreds(w, p.ecs.DefaultCreds.Creds)
}

func (p DefaultHandler) Put(w http.ResponseWriter, r *http.Request) {
	creds, err := ecs.ReadClientRequest(r)
	if err != nil {
		WriteMessage(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if creds.Creds.Expired() {
		Expired(w)
		return
	}

	p.ecs.DefaultCreds = creds
	OK(w)
}

func (p DefaultHandler) Delete(w http.ResponseWriter, r *http.Request) {
	if p.ecs.DefaultCreds.ProfileName == "" {
		Expired(w)
		return
	}

	p.ecs.DefaultCreds = &ecs.ECSClientRequest{
		ProfileName: "",
	}
	OK(w)
}
