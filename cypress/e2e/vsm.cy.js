const path = require("path")

describe('End to End testing of VPN Server Manager', () => {
  it('End to End Success', () => {
    cy.visit('http://vsm.local.kronus.network')
    cy.get('[id="username"]').type("testuser")
    cy.get('[id="kc-login"]').click()
    cy.origin('http://vsm.local.kronus.network', () => {
      cy.window()
      .document()
       .then(function (doc) {
          doc.addEventListener('click', () => {
            setTimeout(function () {
              doc.location.reload()
            }, 10000)
          })
          cy.get('form[action="/api/servers/myserver"] button').click()
        })

        cy.screenshot("success")
      })
      const downloadsFolder = Cypress.config("downloadsFolder")
      cy.readFile(path.join(downloadsFolder, "myserver.ovpn"))
        .should("exist")
        .should("include", "cipher AES-256-CBC")
        .should("include", "auth SHA1")
        .should("include", "remote myvpn.example.com 1194 udp")
        .should("include", "verify-x509-name \"C=CA, ST=Ontario, L=Toronto, O=My Org, emailAddress=admin@example.com, CN=myvpn.example.com\" subject")
        .should("include", "<ca>\n-----BEGIN CERTIFICATE-----\n")
        .should("include", "-----END CERTIFICATE-----\n</ca>")
        .should("include", "<cert>\n-----BEGIN CERTIFICATE-----\n")
        .should("include", "-----END CERTIFICATE-----\n</cert>")
        .should("include", "<key>\n-----BEGIN RSA PRIVATE KEY-----\n")
        .should("include", "-----END RSA PRIVATE KEY-----\n</key>")
        .should("include", "<tls-crypt>\n#\n# 2048 bit OpenVPN static key\n#\n-----BEGIN OpenVPN Static key V1-----\nsingleline\nstatickey\n-----END OpenVPN Static key V1-----\n\n</tls-crypt>")
  })

  it('Bad username', () => {
    cy.visit('http://vsm.local.kronus.network')
    cy.get('[id="username"]').type("baduser")
    cy.get('[id="kc-login"]').click()
    cy.get('div[id="input-error-username"]').should('be.visible')
    cy.screenshot("bad_username")
  })

  it('Not logged in', () => {
    cy.request({
      method: 'POST',
      url: 'http://vsm.local.kronus.network/api/servers/myserver',
      form: true,
      body: {
        csrf_token: 'not-logged-in'
      },
      followRedirect: false,
      failOnStatusCode: false
    }).then((resp) => {
      expect(resp.status).to.eq(401)
      expect(resp.body).to.eq('')
    })
    cy.request({
      url: 'http://vsm.local.kronus.network/api/servers/myserver',
      followRedirect: false,
      failOnStatusCode: false
    }).then((resp) => {
      expect(resp.status).to.eq(405)
    })
    cy.request({
      url: 'http://vsm.local.kronus.network/auth/logout',
      followRedirect: false,
      failOnStatusCode: false
    }).then((resp) => {
      expect(resp.status).to.eq(405)
    })
    cy.screenshot("not_logged_in")
  })

  it('Unknown Server', () => {
    cy.visit('http://vsm.local.kronus.network')
    cy.get('[id="username"]').type("testuser")
    cy.get('[id="kc-login"]').click()
    cy.origin('http://vsm.local.kronus.network', () => {
      cy.get('form[action="/api/servers/myserver"] input[name="csrf_token"]')
        .invoke('val')
        .then((csrfToken) => {
          cy.request({
            method: 'POST',
            url: '/api/servers/badserver',
            form: true,
            body: {
              csrf_token: csrfToken
            },
            followRedirect: false,
            failOnStatusCode: false
          }).then((resp) => {
            expect(resp.status).to.eq(403)
          })
        })
      cy.get('a[class="navbar-brand"').contains("Kronus' Lab - VPN Server Manager")
      cy.screenshot("bad_server")
    })
  })

  it('Who Am I endpoint test', () => {
    cy.visit('http://vsm.local.kronus.network')
    cy.get('[id="username"]').type("testuser")
    cy.get('[id="kc-login"]').click()
    cy.origin('http://vsm.local.kronus.network', () => {
      cy.request('/api/whoami').then((resp) => {
        expect(resp.status).to.eq(200)
        expect(resp.body).to.have.property('username', 'testuser')
        expect(resp.body).to.have.property('vpn_servers').to.be.an('array')
      })
      cy.screenshot("whoami")
    })
  })
})