const legitimateTemplates = [
  'Hi {name}, dinner is at {time} tonight. See you there!',
  'Your library book is due on {day}; renew it in the library app if needed.',
  'The team meeting moved to {time}. Please bring the project notes.',
  'Reminder: your dentist appointment is on {day} at {time}.',
  'Your parcel is scheduled for delivery on {day}. Track it in the official app.',
  'Happy birthday {name}! Hope you have a wonderful day.',
  'The electricity maintenance window is {time}; service may be unavailable briefly.',
  'Please review the shared document before our meeting tomorrow.',
  'Your train leaves at {time} from platform 3. Have a safe journey.',
  'The community class is cancelled on {day} and resumes next week.',
];
const suspiciousTemplates = [
  'Urgent: your bank account will be suspended. Verify your OTP and PIN immediately.',
  'Your KYC is incomplete. Send your PAN card and password today or your account will close.',
  'Your UPI refund is waiting. Pay a processing fee now to receive the cashback.',
  'Congratulations, guaranteed work from home job. Pay the registration fee today.',
  'Invest now for guaranteed profit and double your money. Transfer the entry fee immediately.',
  'Security team alert: click the link to verify your password or your account will be blocked.',
  'You won a prize. Pay the delivery fee by UPI immediately to claim your reward.',
  'Final notice from the bank: share your OTP and card number to prevent suspension.',
  'A recruiter offers guaranteed income. Send the investment deposit today to start.',
  'Police complaint pending: update your account PIN immediately through this portal.',
];
const names = ['Asha', 'Ravi', 'Mina', 'Arun', 'Leela'];
const times = ['7pm', '8am', '2:30pm', 'noon', '6pm'];
const days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday'];
const legitimate = legitimateTemplates.flatMap((template) => names.map((name, index) => ({ type: 'message', content: template.replace('{name}', name).replace('{time}', times[index]).replace('{day}', days[index]), label: 'legitimate' })));
const suspicious = suspiciousTemplates.flatMap((content) => [0, 1, 2, 3, 4].map((index) => ({ type: 'message', content: `${content} Case ${index + 1}.`, label: 'suspicious' })));
module.exports = [...legitimate, ...suspicious];
