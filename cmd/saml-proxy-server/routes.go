package main

func (s *server) routes() {
	s.router.HandleFunc("/saml", s.handleSAML())
	s.router.HandleFunc("/", s.handleIndex())
}
