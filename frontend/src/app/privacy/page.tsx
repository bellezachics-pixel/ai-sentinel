import LegalPage from "@/components/legal/LegalPage";

export default function PrivacyPage() {
  return (
    <LegalPage
      title="Privacidad"
      updated="3 de julio de 2026"
      sections={[
        {
          heading: "Datos de cuenta",
          body: "AI Sentinel usa tu cuenta para darte acceso al panel, mantener tu sesion y asociar actividad basica de uso. Si entras con Google, recibimos el email verificado necesario para crear tu cuenta.",
        },
        {
          heading: "Contenido analizado",
          body: "Los textos, URLs, archivos o mensajes que envias se procesan para generar analisis de riesgo y recomendaciones. Evita subir secretos, contrasenas, documentos legales sensibles o informacion personal que no sea necesaria para el analisis.",
        },
        {
          heading: "Proveedores externos",
          body: "Algunas funciones pueden usar servicios externos como OpenAI, VirusTotal, Google Fact Check, Numverify o Twilio cuando sus API keys esten configuradas. Cada proveedor puede procesar datos conforme a sus propias politicas.",
        },
        {
          heading: "Seguridad",
          body: "La app aplica autenticacion, controles de CORS y protecciones basicas contra abuso. Ningun sistema es infalible, por lo que los resultados deben tratarse como apoyo para tomar decisiones, no como garantia absoluta.",
        },
        {
          heading: "Contacto",
          body: "Para solicitar correcciones, eliminacion de datos o soporte, usa el canal comercial o de soporte definido para tu instalacion de AI Sentinel.",
        },
      ]}
    />
  );
}
