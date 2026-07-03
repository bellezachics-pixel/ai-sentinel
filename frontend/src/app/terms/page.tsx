import LegalPage from "@/components/legal/LegalPage";

export default function TermsPage() {
  return (
    <LegalPage
      title="Terminos de uso"
      updated="3 de julio de 2026"
      sections={[
        {
          heading: "Uso permitido",
          body: "AI Sentinel esta pensado para ayudar a identificar riesgos de ciberseguridad, phishing, fraude, archivos sospechosos y senales de desinformacion. Debe usarse sobre contenido propio, autorizado o recibido por el usuario.",
        },
        {
          heading: "Limitaciones",
          body: "Los analisis pueden tener falsos positivos o falsos negativos. La app no reemplaza auditorias profesionales, asesoramiento legal, respuesta a incidentes ni investigacion forense especializada.",
        },
        {
          heading: "Cuentas",
          body: "El usuario es responsable de proteger su cuenta, cerrar sesion en dispositivos compartidos y no intentar acceder a cuentas, datos o sistemas de terceros sin autorizacion.",
        },
        {
          heading: "Servicios premium",
          body: "Algunas funciones pueden marcarse como premium o avanzadas. La disponibilidad, precio y alcance pueden cambiar segun el plan comercial contratado.",
        },
        {
          heading: "Cambios",
          body: "Estos terminos pueden actualizarse para reflejar nuevas funciones, integraciones, requisitos legales o cambios de operacion del servicio.",
        },
      ]}
    />
  );
}
