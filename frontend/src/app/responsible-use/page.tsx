import LegalPage from "@/components/legal/LegalPage";

export default function ResponsibleUsePage() {
  return (
    <LegalPage
      title="Uso responsable"
      updated="3 de julio de 2026"
      sections={[
        {
          heading: "Finalidad defensiva",
          body: "AI Sentinel debe usarse para proteccion, educacion, verificacion de riesgos y apoyo a decisiones de seguridad. No debe usarse para atacar, evadir controles, acosar, doxxear ni comprometer sistemas.",
        },
        {
          heading: "Archivos y enlaces",
          body: "Solo analiza archivos, URLs o mensajes que tengas derecho a revisar. No subas malware activo, datos robados, credenciales de terceros o contenido ilegal.",
        },
        {
          heading: "Resultados",
          body: "Las recomendaciones son orientativas. Antes de bloquear usuarios, eliminar cuentas, denunciar o tomar acciones sensibles, confirma con fuentes adicionales y criterio humano.",
        },
        {
          heading: "Privacidad de terceros",
          body: "Evita usar la herramienta para investigar personas sin base legitima. Respeta privacidad, leyes locales, politicas internas y consentimiento cuando aplique.",
        },
        {
          heading: "Abuso",
          body: "El uso abusivo puede resultar en suspension de cuenta, restriccion de acceso o bloqueo de funciones, especialmente si afecta la seguridad o disponibilidad del servicio.",
        },
      ]}
    />
  );
}
