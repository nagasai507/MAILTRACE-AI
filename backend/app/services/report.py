from io import BytesIO
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,Table,TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

def make_pdf(case,a):
 b=BytesIO();doc=SimpleDocTemplate(b,pagesize=A4,leftMargin=40,rightMargin=40,topMargin=40,bottomMargin=40);s=getSampleStyleSheet();story=[Paragraph('MAILTRACE AI — FORENSIC INTELLIGENCE REPORT',s['Title']),Paragraph(case.case_number,s['Heading2']),Spacer(1,10)]
 rows=[['Classification',a['classification']],['Risk',f"{a['risk_score']}/100"],['Priority',a['priority']],['Subject',a['subject']],['Sender',a['sender']],['Evidence SHA-256',case.evidence_hash]]
 t=Table(rows,colWidths=[140,370]);t.setStyle(TableStyle([('GRID',(0,0),(-1,-1),.5,colors.grey),('BACKGROUND',(0,0),(0,-1),colors.HexColor('#eaf0f4'))]));story+=[t,Spacer(1,15),Paragraph('Why flagged',s['Heading2'])]
 for x in a['reasons']:story.append(Paragraph('• '+x,s['BodyText']))
 story += [Spacer(1,10),Paragraph('Authentication',s['Heading2']),Table([['SPF',a['authentication']['spf']],['DKIM',a['authentication']['dkim']],['DMARC',a['authentication']['dmarc']]],colWidths=[140,370]),Spacer(1,10),Paragraph('Relay path',s['Heading2'])]
 for h in a['relay_hops']:story.append(Paragraph(f"Hop {h['hop']}: {h.get('ip') or 'no public IP'} — {h['raw'][:180]}",s['BodyText']))
 story += [Spacer(1,10),Paragraph('Indicators',s['Heading2']),Paragraph('Domains: '+(', '.join(a['domains']) or 'None'),s['BodyText']),Paragraph('IPs: '+(', '.join(a['public_ips']) or 'None'),s['BodyText']),Paragraph('URLs: '+(', '.join(a['urls']) or 'None'),s['BodyText']),Spacer(1,12),Paragraph('Caution: geolocation is infrastructure intelligence, not proof of a human attacker identity or physical location.',s['Italic'])]
 doc.build(story);b.seek(0);return b
