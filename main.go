package main

import (
	"strings"
	"sync"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

func main() {
	a := app.NewWithID("reco.app")
	w := a.NewWindow("Reco – Reconnaissance Tool")
	w.Resize(fyne.NewSize(700, 700))

	// Output box
	op := widget.NewMultiLineEntry()
	op.SetMinRowsVisible(25)
<<<<<<< HEAD
	op.Resize(fyne.NewSize(680, 600))
=======
	op.Resize(fyne.NewSize(680, 500))
>>>>>>> 5a7964e (Made changes again)
	op.Wrapping = fyne.TextWrapWord
	op.Hide()

	// Input fields
	ip1 := widget.NewEntry()
	ip1.SetPlaceHolder("Enter username (e.g. johndoe)")
	ip1.Hide()

	ip2 := widget.NewEntry()
<<<<<<< HEAD
	ip2.SetPlaceHolder("Enter domain (e.g. example.com)")
=======
	ip2.SetPlaceHolder("Enter domain (e.g. vnrvjiet.ac.in or example.com)")
>>>>>>> 5a7964e (Made changes again)
	ip2.Hide()

	// Buttons
	go1 := widget.NewButtonWithIcon("Run", theme.ConfirmIcon(), func() {
		user := ip1.Text
		if user == "" {
			op.SetText("Please enter a username")
			op.Show()
			return
		}
		op.SetText("Searching for user info...")
		op.Show()

		go func() {
			arr := findUser(user)
			text := strings.Join(arr, "\n")
			// update UI from goroutine
			fyne.CurrentApp().Driver().DoFromGoroutine(func() {
				op.SetText(text)
				op.Show()
			}, true)
		}()
	})
	go1.Hide()

	go2 := widget.NewButtonWithIcon("Run Scan", theme.ConfirmIcon(), func() {
		domain := ip2.Text
		if domain == "" {
			op.SetText("Please enter a domain name")
			op.Show()
			return
		}

<<<<<<< HEAD
		op.SetText("Running scans, please wait...\n Feel free to get a coffee, this will take a while")
=======
		op.SetText("Running scans, please wait...")
>>>>>>> 5a7964e (Made changes again)
		op.Show()

		// Run all scans concurrently but collect structured outputs in a map
		go func() {
			var wg sync.WaitGroup
<<<<<<< HEAD
			results := make(chan string, 11) // buffer for all tools
=======
			outputs := make(map[string]string)
			var mu sync.Mutex
>>>>>>> 5a7964e (Made changes again)

			addResult := func(tool string, out string) {
				mu.Lock()
				outputs[tool] = out
				mu.Unlock()
			}

			// WHOIS
			wg.Add(1)
			go func() {
				defer wg.Done()
				lines, err := whoIs(domain)
				if err != nil {
					addResult("WHOIS", "WHOIS error: "+err.Error())
					return
				}
				addResult("WHOIS", "WHOIS results:\n"+strings.Join(lines, "\n"))
			}()

			// DNS
			wg.Add(1)
			go func() {
				defer wg.Done()
				subs, err := Dns(domain)
				if err != nil {
					addResult("DNS", "DNS error: "+err.Error())
					return
				}
				if len(subs) == 0 {
					addResult("DNS", "No subdomains found.")
					return
				}
				addResult("DNS", "DNS enumeration:\n"+strings.Join(subs, "\n"))
			}()

			// Directory scan
			wg.Add(1)
			go func() {
				defer wg.Done()
				arr := dir(domain)
				if len(arr) == 0 {
					addResult("Directory Scan", "No directories found.")
					return
				}
				addResult("Directory Scan", "Directory scan:\n"+strings.Join(arr, "\n"))
			}()

			// Vhost
			wg.Add(1)
			go func() {
				defer wg.Done()
				hosts, err := vhost(domain)
				if err != nil {
					addResult("VHOST", "VHOST error: "+err.Error())
					return
				}
				if len(hosts) == 0 {
					addResult("VHOST", "No virtual hosts found.")
					return
				}
				addResult("VHOST", "VHOST results:\n"+strings.Join(hosts, "\n"))
			}()

			// Email Harvester
			wg.Add(1)
			go func() {
				defer wg.Done()
				emails, err := emailHarvester(domain)
				if err != nil {
					addResult("Email Harvester", "Email Harvester error: "+err.Error())
					return
				}
				if len(emails) == 0 {
					addResult("Email Harvester", "No emails found.")
					return
				}
				addResult("Email Harvester", "Email Harvester:\n"+FormatEmailResults(emails))
			}()

			// SSL Scanner
			wg.Add(1)
			go func() {
				defer wg.Done()
				ssl, err := sslScanner(domain)
				if err != nil {
					addResult("SSL Scanner", "SSL Scanner error: "+err.Error())
					return
				}
				addResult("SSL Scanner", "SSL Scanner:\n"+strings.Join(ssl, "\n"))
			}()

			// Technology Detector
			wg.Add(1)
			go func() {
				defer wg.Done()
				techs, err := techDetector(domain)
				if err != nil {
					addResult("Technology Detector", "Technology Detector error: "+err.Error())
					return
				}
				if len(techs) == 0 {
					addResult("Technology Detector", "No technologies detected.")
					return
				}
				addResult("Technology Detector", "Technology Detector:\n"+FormatTechResults(techs))
			}()

			// Web Vulnerability Scanner
			wg.Add(1)
			go func() {
				defer wg.Done()
				vulns, err := webVulnScanner(domain)
				if err != nil {
					addResult("Web Vulnerability Scanner", "Web Vulnerability Scanner error: "+err.Error())
					return
				}
				addResult("Web Vulnerability Scanner", "Web Vulnerability Scanner:\n"+strings.Join(vulns, "\n"))
			}()

			// Nmap
			wg.Add(1)
			go func() {
				defer wg.Done()
				nmapResults, err := RunNmapScans(domain, false)
				if err != nil {
					addResult("Nmap", "Nmap error: "+err.Error())
					return
				}
				addResult("Nmap", "Nmap Results:\n"+nmapResults)
			}()

			// Wait for all scans to complete
			wg.Wait()

			// Generate report in its own goroutine so UI thread remains responsive
			go func() {
				// CreateScanReport is in report.go and returns (filepath, markdown, error)
				path, md, err := CreateScanReport(domain, outputs)
				if err != nil {
					fyne.CurrentApp().Driver().DoFromGoroutine(func() {
						op.SetText("Report generation failed: " + err.Error())
						op.Show()
					}, true)
					return
				}

				// Show preview (clamped size) and saved path in the UI
				fyne.CurrentApp().Driver().DoFromGoroutine(func() {
					preview := md
					if len(preview) > 2400 {
						preview = preview[:2400] + "\n\n...report truncated in UI. Saved to: " + path
					} else {
						preview += "\n\nSaved to: " + path
					}
					op.SetText(preview)
					op.Show()
				}, true)
			}()
<<<<<<< HEAD

			// Collect results
			var final strings.Builder
			for r := range results {
				final.WriteString(r + "\n\n")
			}

			fyne.CurrentApp().Driver().DoFromGoroutine(func() {
				op.SetText(final.String())
				op.Show()
			}, true)
=======
>>>>>>> 5a7964e (Made changes again)
		}()
	})
	go2.Hide()

	// Navigation buttons
	btn1 := widget.NewButtonWithIcon("Find User", theme.AccountIcon(), func() {
		ip1.Show()
		go1.Show()
		ip2.Hide()
		go2.Hide()
		op.Hide()
	})

	btn2 := widget.NewButtonWithIcon("Website Details", theme.ComputerIcon(), func() {
		ip2.Show()
		go2.Show()
		ip1.Hide()
		go1.Hide()
		op.Hide()
	})

	// Layout
	w.SetContent(
		container.NewVBox(
			widget.NewLabelWithStyle("Reco – Reconnaissance Tool", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
			widget.NewSeparator(),
			container.New(layout.NewGridLayout(2), btn1, btn2),
			ip1,
			ip2,
			go1,
			go2,
			widget.NewSeparator(),
			container.NewMax(op),
		),
	)

	w.ShowAndRun()
}
