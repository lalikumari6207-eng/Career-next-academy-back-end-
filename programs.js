// Program fees (rupees). Ye frontend ke data-fee / data-inst se match hona chahiye.
// Fee badalni ho to yahan bhi badlo aur registration.html me bhi.
const REG_FEE = 249; // registration fee (rupees)

const PROGRAMS = {
  'house-of-founders-fellowship': { name: "House of Foundership Fellow", fee: 335000, inst: 4 },
  'aditya-birla-finishing-school': { name: "Aditya Birla Capital Finishing School", fee: 355000, inst: 5 },
  'piramal-relationship-management': { name: "Piramal Relationship Management", fee: 275000, inst: 3 },
  'aviva-direct-sales-executive': { name: "Aviva Direct Sales Executive", fee: 275000, inst: 3 },
  'vedantu-academic-counselor': { name: "Vedantu Academic Counselor", fee: 295000, inst: 4 },
  'hero-relationship-manager': { name: "Hero Relationship Manager", fee: 215000, inst: 3 },
  'finova-business-development-executive': { name: "Finova Business Development Executive", fee: 215000, inst: 3 },
  'kotak-gold-loan': { name: "Kotak Gold Loan", fee: 215000, inst: 3 },
  'mahindra-finance-business-executive': { name: "Mahindra Finance Business Executive", fee: 215000, inst: 3 },
  'rbl-branch-manager': { name: "RBL Branch Manager", fee: 245000, inst: 3 },
  'rbl-premium-banker': { name: "RBL Premium Banker Program", fee: 245000, inst: 3 },
  'idfc-emerging-bankers': { name: "IDFC Emerging Banker Program", fee: 385000, inst: 5 },
  'axis-operational': { name: "Axis Bank Operational Program", fee: 385000, inst: 5 },
  'bandhan-operational': { name: "Bandhan Bank Operational Program", fee: 335000, inst: 4 },
  'bandhan-aspiring-champions': { name: "Bandhan Bank Aspiring Champions", fee: 335000, inst: 4 },
  'axis-assistant-manager': { name: "Axis Bank Assistant Manager", fee: 385000, inst: 5 },
  'hdfc-assistant-manager': { name: "HDFC Assistant Manager", fee: 385000, inst: 5 },
  'kotak-acceleration-customer-service': { name: "Kotak Acceleration Customer Service", fee: 275000, inst: 3 },
  'kotak-next-gen-relationship': { name: "Kotak Next Gen Relationship Program", fee: 385000, inst: 5 },
  'dcb-customer-service-manager': { name: "DCB Customer Service Manager", fee: 215000, inst: 3 },
  'hdfc-deputy-manager': { name: "HDFC Deputy Manager", fee: 385000, inst: 5 },
};

module.exports = { PROGRAMS, REG_FEE };
