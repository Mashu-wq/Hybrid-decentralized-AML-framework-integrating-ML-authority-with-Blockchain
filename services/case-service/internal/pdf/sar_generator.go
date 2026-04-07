// Package pdf generates Suspicious Activity Reports (SARs) as PDF documents.
package pdf

import (
	"bytes"
	"fmt"
	"time"

	"github.com/fraud-detection/case-service/internal/domain"
	"github.com/jung-kurt/gofpdf"
)

// Generator produces SAR PDF documents using gofpdf.
type Generator struct {
	orgName    string
	orgAddress string
}

// NewGenerator creates a Generator with the filing institution details.
func NewGenerator(orgName, orgAddress string) *Generator {
	return &Generator{orgName: orgName, orgAddress: orgAddress}
}

// GenerateSAR produces a FinCEN-style SAR PDF for the given case.
// Returns the PDF bytes; the caller is responsible for uploading to S3.
func (g *Generator) GenerateSAR(c *domain.Case, actions []*domain.CaseAction, evidence []*domain.Evidence) ([]byte, error) {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(20, 20, 20)
	pdf.AddPage()

	// ---------------------------------------------------------------------------
	// Header
	// ---------------------------------------------------------------------------
	pdf.SetFont("Arial", "B", 18)
	pdf.SetTextColor(220, 50, 50)
	pdf.CellFormat(0, 10, "SUSPICIOUS ACTIVITY REPORT (SAR)", "", 1, "C", false, 0, "")

	pdf.SetFont("Arial", "", 10)
	pdf.SetTextColor(100, 100, 100)
	pdf.CellFormat(0, 6, fmt.Sprintf("Generated: %s | Reference: %s", time.Now().UTC().Format(time.RFC3339), c.CaseID), "", 1, "C", false, 0, "")
	pdf.CellFormat(0, 6, fmt.Sprintf("Filing Institution: %s", g.orgName), "", 1, "C", false, 0, "")
	pdf.Ln(5)

	pdf.SetDrawColor(200, 200, 200)
	pdf.Line(20, pdf.GetY(), 190, pdf.GetY())
	pdf.Ln(5)

	// ---------------------------------------------------------------------------
	// Section 1: Case Summary
	// ---------------------------------------------------------------------------
	g.sectionHeader(pdf, "1. CASE SUMMARY")

	fields := [][2]string{
		{"Case ID", c.CaseID},
		{"Alert ID", c.AlertID},
		{"Customer ID", c.CustomerID},
		{"Transaction Hash", c.TxHash},
		{"Case Status", string(c.Status)},
		{"Priority", c.Priority.String()},
		{"Fraud Probability", fmt.Sprintf("%.4f (%.1f%%)", c.FraudProbability, c.FraudProbability*100)},
		{"Risk Score", fmt.Sprintf("%.2f / 100", c.RiskScore)},
		{"Created At", c.CreatedAt.UTC().Format(time.RFC3339)},
		{"Assignee", orNA(c.AssigneeID)},
	}
	g.fieldTable(pdf, fields)

	// ---------------------------------------------------------------------------
	// Section 2: Narrative
	// ---------------------------------------------------------------------------
	g.sectionHeader(pdf, "2. SUSPICIOUS ACTIVITY NARRATIVE")
	pdf.SetFont("Arial", "", 10)
	pdf.SetTextColor(0, 0, 0)

	narrative := c.Description
	if narrative == "" {
		narrative = fmt.Sprintf(
			"This report has been filed pursuant to 31 U.S.C. § 5318(g) and 31 CFR § 1020.320. "+
				"An anomalous transaction (hash: %s) associated with customer %s was flagged by the "+
				"automated AML/fraud detection system with a fraud probability of %.2f%%. "+
				"The transaction exhibited characteristics consistent with potential money laundering activity "+
				"and was escalated for investigation via case %s.",
			c.TxHash, c.CustomerID, c.FraudProbability*100, c.CaseID,
		)
	}
	pdf.MultiCell(0, 6, narrative, "", "L", false)
	pdf.Ln(3)

	if c.ResolutionSummary != "" {
		pdf.SetFont("Arial", "B", 10)
		pdf.Cell(0, 6, "Resolution Summary:")
		pdf.Ln(6)
		pdf.SetFont("Arial", "", 10)
		pdf.MultiCell(0, 6, c.ResolutionSummary, "", "L", false)
		pdf.Ln(3)
	}

	// ---------------------------------------------------------------------------
	// Section 3: Investigation Timeline (actions)
	// ---------------------------------------------------------------------------
	g.sectionHeader(pdf, "3. INVESTIGATION TIMELINE")

	if len(actions) == 0 {
		pdf.SetFont("Arial", "I", 10)
		pdf.Cell(0, 6, "No recorded actions.")
		pdf.Ln(8)
	} else {
		// Table header
		pdf.SetFont("Arial", "B", 9)
		pdf.SetFillColor(230, 230, 230)
		pdf.CellFormat(45, 7, "Timestamp", "1", 0, "C", true, 0, "")
		pdf.CellFormat(35, 7, "Investigator", "1", 0, "C", true, 0, "")
		pdf.CellFormat(35, 7, "Action", "1", 0, "C", true, 0, "")
		pdf.CellFormat(55, 7, "Notes", "1", 1, "C", true, 0, "")

		pdf.SetFont("Arial", "", 9)
		pdf.SetFillColor(255, 255, 255)
		for _, a := range actions {
			pdf.CellFormat(45, 6, a.PerformedAt.UTC().Format("2006-01-02 15:04:05"), "1", 0, "L", false, 0, "")
			pdf.CellFormat(35, 6, truncate(a.InvestigatorID, 18), "1", 0, "L", false, 0, "")
			pdf.CellFormat(35, 6, a.Action, "1", 0, "L", false, 0, "")
			pdf.CellFormat(55, 6, truncate(a.Notes, 28), "1", 1, "L", false, 0, "")
		}
		pdf.Ln(3)
	}

	// ---------------------------------------------------------------------------
	// Section 4: Evidence Inventory
	// ---------------------------------------------------------------------------
	g.sectionHeader(pdf, "4. EVIDENCE INVENTORY")

	if len(evidence) == 0 {
		pdf.SetFont("Arial", "I", 10)
		pdf.Cell(0, 6, "No evidence attached.")
		pdf.Ln(8)
	} else {
		pdf.SetFont("Arial", "B", 9)
		pdf.SetFillColor(230, 230, 230)
		pdf.CellFormat(60, 7, "File Name", "1", 0, "C", true, 0, "")
		pdf.CellFormat(35, 7, "Type", "1", 0, "C", true, 0, "")
		pdf.CellFormat(30, 7, "Size (bytes)", "1", 0, "C", true, 0, "")
		pdf.CellFormat(45, 7, "Uploaded By", "1", 1, "C", true, 0, "")

		pdf.SetFont("Arial", "", 9)
		for _, e := range evidence {
			pdf.CellFormat(60, 6, truncate(e.FileName, 35), "1", 0, "L", false, 0, "")
			pdf.CellFormat(35, 6, string(e.EvidenceType), "1", 0, "L", false, 0, "")
			pdf.CellFormat(30, 6, fmt.Sprintf("%d", e.FileSize), "1", 0, "R", false, 0, "")
			pdf.CellFormat(45, 6, truncate(e.UploadedBy, 22), "1", 1, "L", false, 0, "")
		}
		pdf.Ln(3)
	}

	// ---------------------------------------------------------------------------
	// Section 5: Certifications
	// ---------------------------------------------------------------------------
	g.sectionHeader(pdf, "5. CERTIFICATION")
	pdf.SetFont("Arial", "", 10)
	pdf.MultiCell(0, 6,
		"I hereby certify that, to the best of my knowledge, the information contained in this "+
			"Suspicious Activity Report is accurate and complete. This report is filed in accordance "+
			"with the requirements of the Bank Secrecy Act and FinCEN regulations.",
		"", "L", false)
	pdf.Ln(8)

	pdf.SetFont("Arial", "", 10)
	pdf.Cell(60, 6, "Investigator Signature: ________________________")
	pdf.Ln(6)
	pdf.Cell(60, 6, fmt.Sprintf("Date: %s", time.Now().UTC().Format("January 2, 2006")))
	pdf.Ln(10)

	// ---------------------------------------------------------------------------
	// Footer on all pages
	// ---------------------------------------------------------------------------
	pdf.SetFont("Arial", "I", 8)
	pdf.SetTextColor(150, 150, 150)
	pdf.CellFormat(0, 6, fmt.Sprintf(
		"CONFIDENTIAL — AML Fraud Detection System | %s | Case %s | DO NOT DISTRIBUTE",
		g.orgName, c.CaseID,
	), "", 1, "C", false, 0, "")

	// Collect output
	var buf bytes.Buffer
	if err := pdf.Output(&buf); err != nil {
		return nil, fmt.Errorf("render SAR PDF: %w", err)
	}
	return buf.Bytes(), nil
}

// ---------------------------------------------------------------------------
// PDF helpers
// ---------------------------------------------------------------------------

func (g *Generator) sectionHeader(pdf *gofpdf.Fpdf, title string) {
	pdf.SetFont("Arial", "B", 12)
	pdf.SetTextColor(30, 60, 120)
	pdf.SetFillColor(240, 245, 255)
	pdf.CellFormat(0, 8, title, "LB", 1, "L", true, 0, "")
	pdf.SetTextColor(0, 0, 0)
	pdf.Ln(2)
}

func (g *Generator) fieldTable(pdf *gofpdf.Fpdf, fields [][2]string) {
	pdf.SetFont("Arial", "", 10)
	for _, f := range fields {
		pdf.SetFont("Arial", "B", 10)
		pdf.CellFormat(55, 7, f[0]+":", "", 0, "L", false, 0, "")
		pdf.SetFont("Arial", "", 10)
		pdf.CellFormat(0, 7, f[1], "", 1, "L", false, 0, "")
	}
	pdf.Ln(3)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func orNA(s string) string {
	if s == "" {
		return "N/A"
	}
	return s
}
