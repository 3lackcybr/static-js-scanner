import ScannerClient from '@/components/ScannerClient';
import { getAllCweEntries } from '@/scanner/cweMapper';

export default function HomePage() {
  const cweEntries = getAllCweEntries();
  return <ScannerClient cweEntries={cweEntries} />;
}
